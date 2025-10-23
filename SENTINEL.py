#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SENTINEL — Verificador de CNPJs Baixados

Default: BrasilAPI (sem API key), endpoint path-style:
  https://brasilapi.com.br/api/cnpj/v1/{cnpj}

Compatível também com provedores que exigem auth e/ou query param (?cnpj=...).
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlencode

import requests
from requests.adapters import HTTPAdapter

try:
    from tqdm import tqdm
except Exception:
    tqdm = None


PROGRAM_NAME = "SENTINEL"
PROGRAM_VERSION = "1.1.0"


# ========= util =========

def only_digits(s: str) -> str:
    """Remove todos os caracteres não numéricos de uma string.

    Args:
        s: A string de entrada.

    Returns:
        A string contendo apenas dígitos.
    """
    return re.sub(r"\D+", "", s or "")


def validate_cnpj_digits(cnpj: str) -> bool:
    """Valida os dígitos de um CNPJ.

    Args:
        cnpj: O CNPJ a ser validado, com ou sem formatação.

    Returns:
        True se o CNPJ for válido, False caso contrário.
    """
    cnpj = only_digits(cnpj)
    if len(cnpj) != 14 or len(set(cnpj)) == 1:
        return False

    def calc_digit(nums: str) -> int:
        pesos = [6,5,4,3,2,9,8,7,6,5,4,3,2]
        soma = sum(int(n)*p for n,p in zip(nums, pesos[-len(nums):]))
        r = soma % 11
        return 0 if r < 2 else 11 - r

    base = cnpj[:12]
    d1 = calc_digit(base)
    d2 = calc_digit(base + str(d1))
    return cnpj.endswith(f"{d1}{d2}")


# ========= config/types =========

@dataclass(frozen=True)
class ApiConfig:
    """Configurações da API para consulta de CNPJs.

    Attributes:
        endpoint: URL base da API.
        api_key: Chave de API para autenticação.
        auth_header: Nome do cabeçalho de autenticação.
        auth_scheme: Esquema de autenticação (ex: "Bearer").
        cnpj_param_name: Nome do parâmetro de CNPJ na URL.
        timeout_sec: Timeout para as requisições.
    """
    endpoint: str
    api_key: str = ""                 # vazio = sem auth (BrasilAPI)
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    cnpj_param_name: str = "cnpj"
    timeout_sec: float = 20.0


@dataclass(frozen=True)
class RunConfig:
    """Configurações de execução do script.

    Attributes:
        input_path: Caminho do arquivo de entrada com CNPJs.
        baixados_out: Caminho do arquivo de saída para CNPJs baixados.
        relatorio_out: Caminho do arquivo de relatório em CSV.
        rate_per_sec: Taxa de requisições por segundo.
        log_level: Nível de log (ex: "INFO", "DEBUG").
        verbose: Se True, exibe logs detalhados por CNPJ.
        input_encoding: Encoding do arquivo de entrada.
        output_encoding: Encoding dos arquivos de saída.
    """
    input_path: str
    baixados_out: str
    relatorio_out: str
    rate_per_sec: float = 1.5         # um pouco mais conservador p/ BrasilAPI
    log_level: str = "INFO"
    verbose: bool = False
    input_encoding: str = "utf-8"
    output_encoding: str = "utf-8"


@dataclass(frozen=True)
class StatusInfo:
    """Informações de status de um CNPJ.

    Attributes:
        is_baixado: True se o CNPJ estiver baixado.
        raw_status: Status bruto retornado pela API.
        codigo: Código da situação cadastral.
        descricao: Descrição da situação cadastral.
    """
    is_baixado: bool
    raw_status: str
    codigo: Optional[str]
    descricao: Optional[str]


# ========= logging =========

def setup_logging(level: str) -> None:
    """Configura o logging do script.

    Args:
        level: O nível de log a ser utilizado.
    """
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format=f"%(asctime)s | {PROGRAM_NAME} | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ========= http/api =========

class FatalAuthError(Exception):
    """Exceção para erros fatais de autenticação."""
    pass


def build_headers(cfg: ApiConfig, base_url: str) -> Dict[str, str]:
    """Constrói os cabeçalhos para a requisição HTTP.

    Args:
        cfg: A configuração da API.
        base_url: A URL base da API.

    Returns:
        Um dicionário com os cabeçalhos.
    """
    headers: Dict[str, str] = {"Accept": "application/json"}
    needs_auth = bool(cfg.api_key) and ("brasilapi.com.br" not in base_url)
    if needs_auth:
        headers[cfg.auth_header or "Authorization"] = (
            f"{cfg.auth_scheme} {cfg.api_key}" if cfg.auth_scheme else cfg.api_key
        )
    return headers


def _looks_path_style(base: str) -> bool:
    """Verifica se a URL base parece ser do tipo "path-style".

    Args:
        base: A URL base da API.

    Returns:
        True se a URL parece ser "path-style", False caso contrário.
    """
    if "brasilapi.com.br" in base and "?" not in base:
        return True
    return False


def build_url(cfg: ApiConfig, cnpj: str) -> str:
    """Constrói a URL completa para a consulta do CNPJ.

    Args:
        cfg: A configuração da API.
        cnpj: O CNPJ a ser consultado.

    Returns:
        A URL completa para a consulta.
    """
    base = (cfg.endpoint or "").strip() or "https://brasilapi.com.br/api/cnpj/v1"
    # Adicionado re.IGNORECASE para suportar {cnpj}, {CNPJ}, etc.
    if re.search(r"\{cnpj\}", base, re.IGNORECASE):
        return re.sub(r"\{cnpj\}", cnpj, base, flags=re.IGNORECASE)
    if _looks_path_style(base):
        return f"{base.rstrip('/')}/{cnpj}"
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode({cfg.cnpj_param_name or 'cnpj': cnpj})}"


def new_session(pool_connections: int = 64, pool_maxsize: int = 64) -> requests.Session:
    """Cria uma nova sessão de requisições HTTP.

    Args:
        pool_connections: O número de conexões no pool.
        pool_maxsize: O tamanho máximo do pool.

    Returns:
        Uma nova sessão de requisições.
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
    """Realiza uma requisição HTTP com tratamento de erros e retentativas.

    Args:
        session: A sessão de requisições.
        url: A URL para a requisição.
        headers: Os cabeçalhos da requisição.
        timeout: O timeout da requisição.
        max_retries: O número máximo de retentativas.
        backoff: O fator de backoff exponencial para retentativas.

    Returns:
        Uma tupla com o status HTTP, os dados da resposta e uma mensagem de erro.
    """
    err: Optional[str] = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            status = resp.status_code

            if status in (401, 403):
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
                logging.warning("HTTP 429. Aguardando %ss e tentando novamente...", sleep_s)
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

            try:
                data = resp.json()
                err = data.get("message") or data.get("erro") or f"HTTP {status}"
            except Exception:
                data = None
                err = f"HTTP {status}"
            return status, data, err

        except FatalAuthError:
            raise
        except Exception as e:
            err = str(e)
            if attempt < max_retries:
                sleep_s = backoff ** attempt
                logging.warning("Erro de rede: %s. Retentando em %ss...", err, sleep_s)
                time.sleep(sleep_s)
                continue
            return 0, None, err

    return 0, None, err or "Erro desconhecido"


# ========= status decode =========

def _deep_get(obj: Any, path: Sequence[str]) -> Optional[Any]:
    """Acessa um valor aninhado em um dicionário.

    Args:
        obj: O dicionário.
        path: Uma sequência de chaves para acessar o valor.

    Returns:
        O valor encontrado ou None.
    """
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _pick_first(payload: Dict[str, Any], *candidates: Sequence[str]) -> Optional[Any]:
    """Retorna o primeiro valor encontrado de uma lista de caminhos possíveis.

    Args:
        payload: O dicionário de dados.
        *candidates: Uma lista de caminhos (sequências de chaves).

    Returns:
        O primeiro valor encontrado ou None.
    """
    for path in candidates:
        val = _deep_get(payload, path)
        if val is not None:
            return val
    return None


def decode_status(payload: Dict[str, Any]) -> StatusInfo:
    """Decodifica o status de um CNPJ a partir do payload da API.

    Args:
        payload: O payload de dados da API.

    Returns:
        Uma instância de StatusInfo com as informações de status.
    """
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
    if codigo is not None:
        raw_candidates.append(str(codigo))
    if descricao is not None:
        raw_candidates.append(str(descricao))

    for base in ((), ("estabelecimento",), ("empresa",), ("dados",)):
        for k in ("situacao", "status", "situacao_cadastral", "descricao_situacao_cadastral"):
            path = (*base, k)
            v = _deep_get(payload, path)
            if v is not None:
                s_v = str(v)
                if s_v not in raw_candidates:
                    raw_candidates.append(s_v)

    raw_status = " | ".join(x for x in raw_candidates if x).strip() or "<indefinido>"

    is_baixado = False
    if codigo is not None:
        s = str(codigo).strip().upper()
        is_baixado = s in {"4", "04", "BAIXADA", "BAIXADO"}

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
    """Desembrulha o payload de dados da API, se necessário.

    Args:
        data: Os dados da resposta da API.

    Returns:
        O dicionário de dados do payload.
    """
    if isinstance(data, dict):
        if isinstance(data.get("data"), dict):
            return data["data"]
        if isinstance(data.get("result"), dict):
            return data["result"]
    return data if isinstance(data, dict) else {}


# ========= pacing =========

class Pacer:
    """Controlador de ritmo para requisições."""
    __slots__ = ("target_gap", "_last_start")
    def __init__(self, rate_per_sec: float):
        """Inicializa o Pacer.

        Args:
            rate_per_sec: A taxa de requisições por segundo.
        """
        self.target_gap = 1.0 / max(rate_per_sec, 0.1)
        self._last_start = 0.0
    def wait(self) -> None:
        """Aguarda o tempo necessário para manter a taxa de requisições."""
        now = time.perf_counter()
        if self._last_start <= 0.0:
            self._last_start = now
            return
        elapsed = now - self._last_start
        if elapsed < self.target_gap:
            time.sleep(self.target_gap - elapsed)
        self._last_start = time.perf_counter()


# ========= IO / fluxo principal =========

def read_cnpjs(path: str, encoding: str = "utf-8") -> Tuple[List[str], List[str], int]:
    """Lê, normaliza e valida CNPJs de um arquivo de texto.

    Args:
        path: O caminho para o arquivo de texto.
        encoding: O encoding do arquivo.

    Returns:
        Uma tupla com:
        - A lista de CNPJs válidos (deduplicados e na ordem de aparição).
        - A lista de entradas inválidas (não foram validadas).
        - A contagem de CNPJs que foram normalizados com zeros à esquerda.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Arquivo de entrada não encontrado: {path}")
    with open(path, "r", encoding=encoding) as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    seen: set[str] = set()
    cnpjs: List[str] = []
    invalids: List[str] = []
    normalized_count = 0
    for line in raw_lines:
        c = only_digits(line)
        original_line_is_invalid = True

        # Tenta normalizar se for curto
        if 1 <= len(c) < 14:
            c_filled = c.zfill(14)
            if validate_cnpj_digits(c_filled):
                c = c_filled
                # Se normalizado com sucesso, a linha original é válida
                original_line_is_invalid = False

        # Valida a versão (potencialmente normalizada)
        if validate_cnpj_digits(c):
            if c not in seen:
                seen.add(c)
                cnpjs.append(c)
                # Conta como normalizado apenas se a versão curta foi a primeira a ser vista
                if len(only_digits(line)) < 14:
                    normalized_count += 1
            # Se a linha era válida (diretamente ou após normalização), não a marcamos como inválida
            original_line_is_invalid = False

        if original_line_is_invalid and line not in invalids:
            invalids.append(line)
    return cnpjs, invalids, normalized_count


def row_dict(cnpj: str, status_label: str, info: Optional[StatusInfo], http_status: int, err: Optional[str]) -> Dict[str, Any]:
    """Cria um dicionário de linha para o relatório CSV.

    Args:
        cnpj: O CNPJ.
        status_label: O rótulo do status.
        info: As informações de status do CNPJ.
        http_status: O status HTTP da requisição.
        err: A mensagem de erro, se houver.

    Returns:
        Um dicionário representando a linha do relatório.
    """
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
    """Analisa as variáveis de ambiente para configurar a API.

    Returns:
        Uma instância de ApiConfig com as configurações da API.
    """
    return ApiConfig(
        endpoint=os.getenv("API_BR_ENDPOINT", os.getenv("API_BRASIL_ENDPOINT", "")).strip(),
        api_key=os.getenv("API_BR_API_KEY", os.getenv("API_BRASIL_API_KEY", "")).strip(),
        auth_header=os.getenv("API_BR_AUTH_HEADER", os.getenv("API_BRASIL_AUTH_HEADER", "Authorization")).strip() or "Authorization",
        auth_scheme=os.getenv("API_BR_AUTH_SCHEME", os.getenv("API_BRASIL_AUTH_SCHEME", "Bearer")).strip(),
        cnpj_param_name=os.getenv("API_BR_CNPJ_PARAM_NAME", os.getenv("API_BRASIL_CNPJ_PARAM_NAME", "cnpj")).strip() or "cnpj",
        timeout_sec=float(os.getenv("API_TIMEOUT_SEC", "20")),
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> Tuple[RunConfig, ApiConfig, bool]:
    """Analisa os argumentos da linha de comando.

    Args:
        argv: Uma sequência de argumentos da linha de comando.

    Returns:
        Uma tupla com a configuração de execução, a configuração da API e um booleano
        indicando se apenas a versão foi solicitada.
    """
    p = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description=f"{PROGRAM_NAME} {PROGRAM_VERSION} — Verifica CNPJs (BrasilAPI por padrão) e gera relatórios."
    )
    p.add_argument("--version", action="store_true", help="Mostra a versão e sai.")
    p.add_argument("--input", default="cnpjs.txt", help="Arquivo .txt com um CNPJ por linha (default: cnpjs.txt)")
    p.add_argument("--baixados-out", default="baixados_na_receita.txt",
                   help="TXT apenas com CNPJs baixados (default: baixados_na_receita.txt)")
    p.add_argument("--relatorio-out", default="relatorio.csv",
                   help="CSV com cnpj,status,codigo_situacao,descricao_situacao,raw_status,http_status,error (default: relatorio.csv)")
    p.add_argument("--rate", type=float, default=float(os.getenv("API_RATE_PER_SEC", "1.5")),
                   help="Requisições por segundo (default: 1.5)")
    p.add_argument("--timeout", type=float, default=float(os.getenv("API_TIMEOUT_SEC", "20")),
                   help="Timeout por request em segundos (default: 20)")
    p.add_argument("--log-level", default="INFO", help="Nível de log (DEBUG, INFO, WARNING, ERROR).")
    p.add_argument("--verbose", action="store_true", help="Mostra uma linha por CNPJ com resultado.")
    p.add_argument("--input-encoding", default="utf-8", help="Encoding do arquivo de entrada.")
    p.add_argument("--output-encoding", default="utf-8", help="Encoding dos arquivos de saída.")
    p.add_argument("--endpoint", default=None,
                   help="Override do endpoint (ex.: https://brasilapi.com.br/api/cnpj/v1). Se omitido, usa BrasilAPI.")
    args = p.parse_args(argv)

    if args.version:
        print(f"{PROGRAM_NAME} {PROGRAM_VERSION}")
        return RunConfig("", "", ""), ApiConfig(""), True

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
    endpoint = args.endpoint if args.endpoint is not None else env_api_cfg.endpoint
    if not endpoint:
        endpoint = "https://brasilapi.com.br/api/cnpj/v1"

    api_cfg = ApiConfig(
        endpoint=endpoint,
        api_key=env_api_cfg.api_key,                # vazio por padrão (BrasilAPI)
        auth_header=env_api_cfg.auth_header,
        auth_scheme=env_api_cfg.auth_scheme,
        cnpj_param_name=env_api_cfg.cnpj_param_name,
        timeout_sec=args.timeout if args.timeout else env_api_cfg.timeout_sec,
    )

    return run_cfg, api_cfg, False


# ========= main =========

def main(argv: Optional[Sequence[str]] = None) -> int:
    """Função principal do script.

    Args:
        argv: Uma sequência de argumentos da linha de comando.

    Returns:
        O código de saída do script.
    """
    run_cfg, api_cfg, just_version = parse_args(argv)
    if just_version:
        return 0

    setup_logging(run_cfg.log_level)
    logging.info("%s %s iniciado. Endpoint: %s", PROGRAM_NAME, PROGRAM_VERSION, api_cfg.endpoint)

    interrupted = {"flag": False}
    def _handle_sig(signum, frame):
        interrupted["flag"] = True
        logging.warning("Interrompido por sinal %s. Finalizando com segurança...", signum)
    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    try:
        cnpjs, invalids, normalized_count = read_cnpjs(run_cfg.input_path, encoding=run_cfg.input_encoding)
        if normalized_count > 0:
            logging.info("Normalizados com zeros à esquerda: %d", normalized_count)
    except FileNotFoundError as e:
        logging.error(str(e))
        return 2

    if invalids:
        logging.warning("Atenção: %d CNPJ(s) inválido(s) serão ignorados.", len(invalids))
    if not cnpjs:
        logging.error("Nenhum CNPJ válido em '%s'.", run_cfg.input_path)
        return 3

    session = new_session()
    headers = build_headers(api_cfg, api_cfg.endpoint)

    fieldnames = ["cnpj", "status", "codigo_situacao", "descricao_situacao", "raw_status", "http_status", "error"]
    pacer = Pacer(run_cfg.rate_per_sec)

    total = len(cnpjs)
    baixados_count = 0
    iterator: Iterable[str] = tqdm(cnpjs, desc="Consultando CNPJs", unit="cnpj") if tqdm else cnpjs

    try:
        with open(run_cfg.baixados_out, "w", encoding=run_cfg.output_encoding) as f_baix, \
             open(run_cfg.relatorio_out, "w", newline="", encoding=run_cfg.output_encoding) as f_csv:

            writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
            writer.writeheader()

            for idx, cnpj in enumerate(iterator, start=1):
                if interrupted["flag"]:
                    break

                pacer.wait()
                url = build_url(api_cfg, cnpj)

                try:
                    http_status, data, err = safe_request(session, url, headers, timeout=api_cfg.timeout_sec)
                except FatalAuthError as fae:
                    logging.error("Falha de autenticação: %s", fae)
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
        logging.warning("Interrompido (Ctrl+C). Saída parcial foi gravada.")
    finally:
        if invalids:
            preview = "\n".join(f" - {x}" for x in invalids[:10])
            more = f"\n... e mais {len(invalids)-10} inválidos." if len(invalids) > 10 else ""
            logging.warning("CNPJs inválidos ignorados:\n%s%s", preview, more)

    logging.info("Concluído. %d CNPJ(s) BAIXADOS salvos em: %s", baixados_count, run_cfg.baixados_out)
    logging.info("Relatório detalhado salvo em: %s", run_cfg.relatorio_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
