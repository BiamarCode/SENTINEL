#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_cnpjs_apibrasil.py

Objetivo
--------
Ler CNPJs de um arquivo texto, consultar um endpoint de CNPJ de um provedor estilo "API Brasil",
inferir se estão BAIXADOS e gerar:
  1) Um TXT contendo apenas os CNPJs baixados (um por linha)
  2) Um CSV detalhado com colunas: cnpj, status, codigo_situacao, descricao_situacao, raw_status, http_status, error

Destaques técnicos
------------------
- Validação correta de CNPJ (dígitos verificadores)
- Deduplicação preservando ordem
- requests.Session com connection pooling
- Respeito a HTTP 429 (Retry-After), aborta cedo em 401/403
- Backoff exponencial para 5xx e erros transitórios
- Pacing de taxa efetiva (alvo: RPS configurável)
- Flush incremental de arquivos + interrupção segura (Ctrl+C)
- Heurística de status prioriza códigos oficiais (ex.: 04=BAIXADA), com fallback semântico
- Logging configurável (--log-level) e modo verboso (--verbose)

Uso
---
1) Crie 'cnpjs.txt' com um CNPJ por linha (com ou sem máscara).
2) Exporte as variáveis de ambiente (ou use defaults/CLI):

   API_BRASIL_API_KEY         -> chave/token
   API_BRASIL_ENDPOINT        -> URL base (ex.: https://api.apibrasil.com.br/cnpj/v1/consulta)
   API_BRASIL_AUTH_HEADER     -> nome do header de auth (default: Authorization)
   API_BRASIL_AUTH_SCHEME     -> esquema do header (default: Bearer)  => "Authorization: Bearer <API_KEY>"
   API_BRASIL_CNPJ_PARAM_NAME -> nome do parâmetro de query (default: cnpj)
   API_RATE_PER_SEC           -> RPS (default: 2.0)
   API_TIMEOUT_SEC            -> timeout por request, em s (default: 20)

3) Execute:
   python check_cnpjs_apibrasil.py --input cnpjs.txt --baixados-out baixados_na_receita.txt --relatorio-out relatorio.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter

try:
    from tqdm import tqdm  # opcional (barra de progresso)
except Exception:
    tqdm = None


# =========================
# Utilidades de domínio
# =========================

def only_digits(s: str) -> str:
    """Remove tudo que não é dígito."""
    return re.sub(r'\D+', '', s or '')


def validate_cnpj_digits(cnpj: str) -> bool:
    """
    Valida CNPJ (apenas dígitos). Retorna True se válido, False caso contrário.
    Regras: dois dígitos verificadores com pesos cíclicos (5..2,9..2) e (6..2,9..2).
    """
    cnpj = only_digits(cnpj)
    if len(cnpj) != 14 or len(set(cnpj)) == 1:
        return False

    def calc_digit(numeros: str) -> int:
        pesos = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
        soma = sum(int(n) * p for n, p in zip(numeros, pesos[-len(numeros):]))
        resto = soma % 11
        return 0 if resto < 2 else 11 - resto

    base = cnpj[:12]
    d1 = calc_digit(base)
    d2 = calc_digit(base + str(d1))
    return cnpj.endswith(f"{d1}{d2}")


# =========================
# Configuração / Tipos
# =========================

@dataclass(frozen=True)
class ApiConfig:
    endpoint: str
    api_key: str
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    cnpj_param_name: str = "cnpj"
    timeout_sec: float = 20.0


@dataclass(frozen=True)
class RunConfig:
    input_path: str
    baixados_out: str
    relatorio_out: str
    rate_per_sec: float = 2.0
    log_level: str = "INFO"
    verbose: bool = False
    input_encoding: str = "utf-8"
    output_encoding: str = "utf-8"


@dataclass(frozen=True)
class StatusInfo:
    is_baixado: bool
    raw_status: str
    codigo: Optional[str]
    descricao: Optional[str]


# =========================
# Logging
# =========================

def setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# =========================
# HTTP / API helpers
# =========================

class FatalAuthError(Exception):
    """Erros 401/403: abortar execução (credenciais inválidas / acesso negado)."""


def build_headers(cfg: ApiConfig) -> Dict[str, str]:
    if not cfg.api_key:
        raise RuntimeError("Defina API_BRASIL_API_KEY (chave da API).")
    headers = {
        cfg.auth_header or "Authorization": f"{cfg.auth_scheme} {cfg.api_key}" if cfg.auth_scheme else cfg.api_key,
        "Accept": "application/json",
        # Alguns provedores exigem também:
        # "Content-Type": "application/json",
    }
    return headers


def build_url(cfg: ApiConfig, cnpj: str) -> str:
    base = (cfg.endpoint or "").strip()
    if not base:
        raise RuntimeError("Defina API_BRASIL_ENDPOINT (URL base do endpoint de CNPJ).")
    param_name = cfg.cnpj_param_name or "cnpj"
    if "?" in base:
        return f"{base}&{urlencode({param_name: cnpj})}"
    return f"{base}?{urlencode({param_name: cnpj})}"


def new_session(pool_connections: int = 64, pool_maxsize: int = 64) -> requests.Session:
    """
    Cria uma sessão com connection pooling. Re-uso de conexão reduz latência e overhead de TLS.
    Deixamos retries do urllib3 desabilitados (max_retries=0) para controlar manualmente a política.
    """
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def safe_request(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    timeout: float,
    *,
    max_retries: int = 3,
    backoff: float = 1.5,
) -> Tuple[int, Optional[Dict[str, Any]], Optional[str]]:
    """
    Política de robustez:
    - 401/403: erro fatal de autenticação -> lança FatalAuthError
    - 429: respeita Retry-After (se houver), senão usa backoff progressivo
    - 5xx: backoff e retry
    - 200: tenta JSON; se houver "error/erro" no corpo, devolve erro
    - Outras respostas: retorna com melhor mensagem possível
    """
    err: Optional[str] = None

    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            status = resp.status_code

            if status in (401, 403):
                # Mensagem detalhada para diagnóstico
                try:
                    payload = resp.json()
                    msg = payload.get("message") or payload.get("erro") or resp.text
                except Exception:
                    msg = resp.text
                raise FatalAuthError(f"Auth error {status}: {msg}")

            if status == 429 and attempt < max_retries:
                retry_after_hdr = resp.headers.get("Retry-After")
                try:
                    sleep_s = float(retry_after_hdr) if retry_after_hdr else backoff ** attempt
                except Exception:
                    sleep_s = backoff ** attempt
                logging.warning("HTTP 429 recebido. Aguardando %ss antes de tentar novamente...", sleep_s)
                time.sleep(sleep_s)
                continue

            if status == 200:
                try:
                    data = resp.json()
                except Exception:
                    return status, None, "Falha ao decodificar JSON"
                if isinstance(data, dict) and any(k in data for k in ("error", "erro")):
                    return status, data, str(data.get("error") or data.get("erro") or "Erro no corpo da resposta")
                return status, data, None

            if 500 <= status < 600 and attempt < max_retries:
                sleep_s = backoff ** attempt
                logging.warning("HTTP %s. Tentativa %s/%s em %ss...", status, attempt, max_retries, sleep_s)
                time.sleep(sleep_s)
                continue

            # Demais códigos (404, 400, etc.)
            try:
                data = resp.json()
                err = data.get("message") or data.get("erro") or f"HTTP {status}"
            except Exception:
                data = None
                err = f"HTTP {status}"
            return status, data, err

        except FatalAuthError:
            raise  # propagar para abortar no chamador
        except Exception as e:
            err = str(e)
            if attempt < max_retries:
                sleep_s = backoff ** attempt
                logging.warning("Erro de rede: %s. Tentando de novo em %ss...", err, sleep_s)
                time.sleep(sleep_s)
                continue
            return 0, None, err

    return 0, None, err or "Erro desconhecido"


# =========================
# Decodificação de Status
# =========================

def _deep_get(obj: Any, path: Sequence[str]) -> Optional[Any]:
    """Busca segura em dicionários aninhados: _deep_get(data, ["empresa", "situacao"])."""
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _pick_first(payload: Dict[str, Any], *candidates: Sequence[str]) -> Optional[Any]:
    """Varre caminhos candidatos e retorna o primeiro valor não-nulo."""
    for path in candidates:
        val = _deep_get(payload, path)
        if val is not None:
            return val
    return None


def decode_status(payload: Dict[str, Any]) -> StatusInfo:
    """
    Decodifica status priorizando códigos oficiais. Convenções comuns:
      - codigo_situacao_cadastral == 01 ATIVA, 02 SUSPENSA, 03 INAPTA, 04 BAIXADA
      - descricao_situacao_cadastral: texto descritivo
      - 'situacao'/'status' em nível raiz ou aninhado (estabelecimento/empresa/dados)

    Retorna:
      StatusInfo(is_baixado, raw_status, codigo, descricao)
    """
    # Candidatos de caminho para código e descrição:
    codigo = _pick_first(
        payload,
        ("codigo_situacao_cadastral",),
        ("situacao_cadastral", "codigo"),
        ("estabelecimento", "situacao_cadastral"),
        ("empresa", "situacao_cadastral"),
    )
    descricao = _pick_first(
        payload,
        ("descricao_situacao_cadastral",),
        ("situacao",),
        ("status",),
        ("situacao_cadastral", "descricao"),
        ("estabelecimento", "situacao"),
        ("empresa", "situacao"),
    )

    raw_candidates: List[str] = []
    for base in ((), ("estabelecimento",), ("empresa",), ("dados",)):
        for k in ("situacao", "status", "situacao_cadastral", "descricao_situacao_cadastral"):
            path = (*base, k)
            v = _deep_get(payload, path)
            if v is not None:
                raw_candidates.append(str(v))
    raw_status = " | ".join(x for x in raw_candidates if x).strip() or (str(descricao) if descricao else "<indefinido>")

    # Decisão por código (preferencial)
    is_baixado = False
    if codigo is not None:
        s = str(codigo).strip().upper()
        # suportar "04", "4", "BAIXADA", "BAIXADO"
        is_baixado = s in {"4", "04", "BAIXADA", "BAIXADO"}

    # Fallback textual conservador
    if not is_baixado:
        s = (raw_status or "").lower()
        baix_terms = ("baixad", "baixa definitiva", "baixa em", "situacao: baix")
        is_baixado = any(t in s for t in baix_terms)

    return StatusInfo(
        is_baixado=bool(is_baixado),
        raw_status=raw_status or "<indefinido>",
        codigo=str(codigo) if codigo is not None else None,
        descricao=str(descricao) if descricao is not None else None,
    )


def unwrap_payload(data: Any) -> Dict[str, Any]:
    """Desembrulha padrões comuns: {'data': {...}} ou {'result': {...}}."""
    if isinstance(data, dict):
        if isinstance(data.get("data"), dict):
            return data["data"]
        if isinstance(data.get("result"), dict):
            return data["result"]
    return data if isinstance(data, dict) else {}


# =========================
# Pacing (rate control)
# =========================

class Pacer:
    """
    Controla a taxa efetiva (RPS). Implementação simples por intervalo-alvo: garante
    que o tempo entre inícios sucessivos de requisições seja >= target_gap.
    """
    __slots__ = ("target_gap", "_last_start")

    def __init__(self, rate_per_sec: float):
        self.target_gap = 1.0 / max(rate_per_sec, 0.1)
        self._last_start = 0.0

    def wait(self) -> None:
        now = time.perf_counter()
        # Primeira chamada: não dorme
        if self._last_start <= 0.0:
            self._last_start = now
            return
        elapsed = now - self._last_start
        if elapsed < self.target_gap:
            time.sleep(self.target_gap - elapsed)
        self._last_start = time.perf_counter()


# =========================
# IO / fluxo principal
# =========================

def read_cnpjs(path: str, encoding: str = "utf-8") -> Tuple[List[str], List[str]]:
    """
    Lê linhas, normaliza, valida e deduplica preservando ordem.
    Retorna (cnpjs_validos, linhas_invalidas_originais).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Arquivo de entrada não encontrado: {path}")

    with open(path, "r", encoding=encoding) as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    seen: set[str] = set()
    cnpjs: List[str] = []
    invalids: List[str] = []
    for line in raw_lines:
        c = only_digits(line)
        if validate_cnpj_digits(c):
            if c not in seen:
                seen.add(c)
                cnpjs.append(c)
        else:
            invalids.append(line)

    return cnpjs, invalids


def write_csv_header(writer: csv.DictWriter) -> None:
    writer.writeheader()


def row_dict(
    cnpj: str,
    status_label: str,
    info: Optional[StatusInfo],
    http_status: int,
    err: Optional[str],
) -> Dict[str, Any]:
    return {
        "cnpj": cnpj,
        "status": status_label,
        "codigo_situacao": (info.codigo if info else ""),
        "descricao_situacao": (info.descricao if info else ""),
        "raw_status": (info.raw_status if info else "<indefinido>"),
        "http_status": http_status,
        "error": err or "",
    }


def parse_env_api_config() -> ApiConfig:
    return ApiConfig(
        endpoint=os.getenv("API_BRASIL_ENDPOINT", "").strip(),
        api_key=os.getenv("API_BRASIL_API_KEY", "").strip(),
        auth_header=os.getenv("API_BRASIL_AUTH_HEADER", "Authorization").strip() or "Authorization",
        auth_scheme=os.getenv("API_BRASIL_AUTH_SCHEME", "Bearer").strip(),
        cnpj_param_name=os.getenv("API_BRASIL_CNPJ_PARAM_NAME", "cnpj").strip() or "cnpj",
        timeout_sec=float(os.getenv("API_TIMEOUT_SEC", "20")),
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> Tuple[RunConfig, ApiConfig]:
    p = argparse.ArgumentParser(description="Verifica CNPJs baixados via API e gera relatórios.")
    p.add_argument("--input", default="cnpjs.txt", help="Arquivo .txt com um CNPJ por linha (default: cnpjs.txt)")
    p.add_argument("--baixados-out", default="baixados_na_receita.txt",
                   help="Arquivo TXT apenas com CNPJs baixados (default: baixados_na_receita.txt)")
    p.add_argument("--relatorio-out", default="relatorio.csv",
                   help="CSV com cnpj,status,codigo_situacao,descricao_situacao,raw_status,http_status,error (default: relatorio.csv)")
    p.add_argument("--rate", type=float, default=float(os.getenv("API_RATE_PER_SEC", "2.0")),
                   help="Requisições por segundo (default: 2.0)")
    p.add_argument("--timeout", type=float, default=float(os.getenv("API_TIMEOUT_SEC", "20")),
                   help="Timeout por request em segundos (default: 20)")
    p.add_argument("--log-level", default="INFO", help="Nível de log (DEBUG, INFO, WARNING, ERROR). Default: INFO")
    p.add_argument("--verbose", action="store_true", help="Mostra uma linha por CNPJ com resultado resumido.")
    p.add_argument("--input-encoding", default="utf-8", help="Encoding do arquivo de entrada. Default: utf-8")
    p.add_argument("--output-encoding", default="utf-8", help="Encoding dos arquivos de saída. Default: utf-8")

    args = p.parse_args(argv)

    run_cfg = RunConfig(
        input_path=args.input,
        baixados_out=args.baixados_out,
        relatorio_out=args.relatorio_out,
        rate_per_sec=max(args.rate, 0.1),
        log_level=args.log_level,
        verbose=bool(args.verbose),
        input_encoding=args.input_encoding,
        output_encoding=args.output_encoding,
    )

    env_api_cfg = parse_env_api_config()
    # prioriza timeout do CLI, se fornecido
    api_cfg = ApiConfig(
        endpoint=env_api_cfg.endpoint,
        api_key=env_api_cfg.api_key,
        auth_header=env_api_cfg.auth_header,
        auth_scheme=env_api_cfg.auth_scheme,
        cnpj_param_name=env_api_cfg.cnpj_param_name,
        timeout_sec=args.timeout if args.timeout else env_api_cfg.timeout_sec,
    )

    return run_cfg, api_cfg


# =========================
# Main
# =========================

def main(argv: Optional[Sequence[str]] = None) -> int:
    run_cfg, api_cfg = parse_args(argv)
    setup_logging(run_cfg.log_level)

    # Tratamento de SIGINT/SIGTERM para garantir flush
    interrupted = {"flag": False}

    def _handle_sigint(signum, frame):
        interrupted["flag"] = True
        logging.warning("Interrompido por sinal %s. Finalizando com segurança...", signum)

    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    # Leitura e validação de CNPJs
    try:
        cnpjs, invalids = read_cnpjs(run_cfg.input_path, encoding=run_cfg.input_encoding)
    except FileNotFoundError as e:
        logging.error(str(e))
        return 2

    if invalids:
        logging.warning("Atenção: %d CNPJ(s) inválido(s) serão ignorados.", len(invalids))

    if not cnpjs:
        logging.error("Nenhum CNPJ válido encontrado em '%s'.", run_cfg.input_path)
        return 3

    # Preparar sessão e cabeçalhos
    headers = build_headers(api_cfg)
    session = new_session()

    # CSV: campos fixos, ordem estável
    fieldnames = ["cnpj", "status", "codigo_situacao", "descricao_situacao", "raw_status", "http_status", "error"]

    # Pacing
    pacer = Pacer(rate_per_sec=run_cfg.rate_per_sec)

    total = len(cnpjs)
    baixados_count = 0

    # Barra de progresso opcional
    iterator: Iterable[str] = tqdm(cnpjs, desc="Consultando CNPJs", unit="cnpj") if tqdm else cnpjs

    # IO com flush incremental
    try:
        with open(run_cfg.baixados_out, "w", encoding=run_cfg.output_encoding) as f_baix, \
             open(run_cfg.relatorio_out, "w", newline="", encoding=run_cfg.output_encoding) as f_csv:

            writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
            write_csv_header(writer)

            for idx, cnpj in enumerate(iterator, start=1):
                if interrupted["flag"]:
                    break

                pacer.wait()  # respeita taxa alvo
                url = build_url(api_cfg, cnpj)

                try:
                    http_status, data, err = safe_request(
                        session, url, headers, timeout=api_cfg.timeout_sec
                    )
                except FatalAuthError as fae:
                    logging.error("Falha de autenticação: %s", fae)
                    # grava o que já temos e aborta
                    break

                info: Optional[StatusInfo] = None
                status_label = "desconhecido"

                if http_status == 200 and data is not None and not err:
                    payload = unwrap_payload(data)
                    try:
                        info = decode_status(payload)
                        status_label = "baixado" if info.is_baixado else "nao_baixado"
                    except Exception as e:
                        err = f"Falha ao interpretar payload: {e}"
                        status_label = "erro_api"
                elif http_status == 0:
                    status_label = "erro_conexao"
                else:
                    status_label = "erro_api"

                if run_cfg.verbose:
                    logging.info("[%d/%d] %s -> %s (HTTP=%s) %s",
                                 idx, total, cnpj, status_label, http_status, f"err={err}" if err else "")

                writer.writerow(row_dict(cnpj, status_label, info, http_status, err))
                f_csv.flush()

                if status_label == "baixado":
                    f_baix.write(cnpj + "\n")
                    f_baix.flush()
                    baixados_count += 1

    except KeyboardInterrupt:
        logging.warning("Interrompido pelo usuário (Ctrl+C). Saída parcial foi gravada.")
    finally:
        # Avisos finais
        if invalids:
            preview = "\n".join(f" - {x}" for x in invalids[:10])
            more = f"\n... e mais {len(invalids) - 10} inválidos." if len(invalids) > 10 else ""
            logging.warning("CNPJs inválidos ignorados:\n%s%s", preview, more)

    logging.info("Concluído. %d CNPJ(s) BAIXADOS salvos em: %s", baixados_count, run_cfg.baixados_out)
    logging.info("Relatório detalhado salvo em: %s", run_cfg.relatorio_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
