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
    return re.sub(r"\D+", "", s or "")


def validate_cnpj_digits(cnpj: str) -> bool:
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
    endpoint: str
    api_key: str = ""                 # vazio = sem auth (BrasilAPI)
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    cnpj_param_name: str = "cnpj"
    timeout_sec: float = 20.0


@dataclass(frozen=True)
class RunConfig:
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
    is_baixado: bool
    raw_status: str
    codigo: Optional[str]
    descricao: Optional[str]


# ========= logging =========

def setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format=f"%(asctime)s | {PROGRAM_NAME} | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ========= http/api =========

class FatalAuthError(Exception):
    pass


def build_headers(cfg: ApiConfig, base_url: str) -> Dict[str, str]:
    """
    Para BrasilAPI (sem auth), envia apenas Accept.
    Se api_key estiver definida (ex.: APIBrasil), envia header de auth.
    """
    headers: Dict[str, str] = {"Accept": "application/json"}
    needs_auth = bool(cfg.api_key) and ("brasilapi.com.br" not in base_url)
    if needs_auth:
        headers[cfg.auth_header or "Authorization"] = (
            f"{cfg.auth_scheme} {cfg.api_key}" if cfg.auth_scheme else cfg.api_key
        )
    return headers


def _looks_path_style(base: str) -> bool:
    """
    Heurística: se houver placeholder {cnpj} OU se parece BrasilAPI (/cnpj/..., /v1, sem '?'),
    tratamos como path-style.
    """
    if "{cnpj}" in base.lower():
        return True
    if "brasilapi.com.br" in base and "?" not in base:
        return True
    if "/cnpj" in base and "?" not in base:
        return True
    return False


def build_url(cfg: ApiConfig, cnpj: str) -> str:
    """
    Auto-detecta forma do endpoint:
      - path-style (ex.: .../cnpj/v1/{cnpj}  ou  .../cnpj/v1)  → .../<cnpj>
      - query-style (ex.: ...?cnpj=) → ...?cnpj=...
      - placeholder-style (.../{cnpj}) → substitui {cnpj}
    Se endpoint não vier, usa BrasilAPI por padrão.
    """
    base = (cfg.endpoint or "").strip() or "https://brasilapi.com.br/api/cnpj/v1"
    if "{cnpj}" in base:
        return base.replace("{cnpj}", cnpj)
    if _looks_path_style(base):
        return f"{base.rstrip('/')}/{cnpj}"
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urlencode({cfg.cnpj_param_name or 'cnpj': cnpj})}"


def new_session(pool_connections: int = 64, pool_maxsize: int = 64) -> requests.Session:
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
    cur = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def _pick_first(payload: Dict[str, Any], *candidates: Sequence[str]) -> Optional[Any]:
    for path in candidates:
        val = _deep_get(payload, path)
        if val is not None:
            return val
    return None


def decode_status(payload: Dict[str, Any]) -> StatusInfo:
    """
    Prioriza códigos quando disponíveis:
      01=ATIVA, 02=SUSPENSA, 03=INAPTA, 04=BAIXADA (convencional)
    Depois cai para match textual conservador.
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
    for base in ((), ("estabelecimento",), ("empresa",), ("dados",)):
        for k in ("situacao", "status", "situacao_cadastral", "descricao_situacao_cadastral"):
            path = (*base, k)
            v = _deep_get(payload, path)
            if v is not None:
                raw_candidates.append(str(v))
    raw_status = " | ".join(x for x in raw_candidates if x).strip() or (str(descricao) if descricao else "<indefinido>")

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
    if isinstance(data, dict):
        if isinstance(data.get("data"), dict):
            return data["data"]
        if isinstance(data.get("result"), dict):
            return data["result"]
    return data if isinstance(data, dict) else {}


# ========= pacing =========

class Pacer:
    __slots__ = ("target_gap", "_last_start")
    def __init__(self, rate_per_sec: float):
        self.target_gap = 1.0 / max(rate_per_sec, 0.1)
        self._last_start = 0.0
    def wait(self) -> None:
        now = time.perf_counter()
        if self._last_start <= 0.0:
            self._last_start = now
            return
        elapsed = now - self._last_start
        if elapsed < self.target_gap:
            time.sleep(self.target_gap - elapsed)
        self._last_start = time.perf_counter()


# ========= IO / fluxo principal =========

def read_cnpjs(path: str, encoding: str = "utf-8") -> Tuple[List[str], List[str]]:
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


def row_dict(cnpj: str, status_label: str, info: Optional[StatusInfo], http_status: int, err: Optional[str]) -> Dict[str, Any]:
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
        endpoint=os.getenv("API_BR_ENDPOINT", os.getenv("API_BRASIL_ENDPOINT", "")).strip(),
        api_key=os.getenv("API_BR_API_KEY", os.getenv("API_BRASIL_API_KEY", "")).strip(),
        auth_header=os.getenv("API_BR_AUTH_HEADER", os.getenv("API_BRASIL_AUTH_HEADER", "Authorization")).strip() or "Authorization",
        auth_scheme=os.getenv("API_BR_AUTH_SCHEME", os.getenv("API_BRASIL_AUTH_SCHEME", "Bearer")).strip(),
        cnpj_param_name=os.getenv("API_BR_CNPJ_PARAM_NAME", os.getenv("API_BRASIL_CNPJ_PARAM_NAME", "cnpj")).strip() or "cnpj",
        timeout_sec=float(os.getenv("API_TIMEOUT_SEC", "20")),
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> Tuple[RunConfig, ApiConfig, bool]:
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
        cnpjs, invalids = read_cnpjs(run_cfg.input_path, encoding=run_cfg.input_encoding)
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
