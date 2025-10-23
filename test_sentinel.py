import pytest
import os
import tempfile
from SENTINEL import build_url, ApiConfig, read_cnpjs

def test_build_url_case_insensitive_placeholder():
    """Testa a construção de URL com placeholder case-insensitive."""
    cfg = ApiConfig(endpoint="https://example.com/api/{CNPJ}")
    cnpj = "12345678901234"
    expected_url = "https://example.com/api/12345678901234"
    assert build_url(cfg, cnpj) == expected_url

def test_build_url_path_style():
    """Testa a construção de URL no estilo 'path-style'."""
    cfg = ApiConfig(endpoint="https://brasilapi.com.br/api/cnpj/v1")
    cnpj = "12345678901234"
    expected_url = "https://brasilapi.com.br/api/cnpj/v1/12345678901234"
    assert build_url(cfg, cnpj) == expected_url

def test_build_url_query_style():
    """Testa a construção de URL no estilo 'query-style'."""
    cfg = ApiConfig(endpoint="https://api.example.com/cnpj", cnpj_param_name="numero")
    cnpj = "12345678901234"
    expected_url = "https://api.example.com/cnpj?numero=12345678901234"
    assert build_url(cfg, cnpj) == expected_url

def test_build_url_default_brasilapi():
    """Testa a construção de URL padrão para a BrasilAPI."""
    cfg = ApiConfig(endpoint="")
    cnpj = "12345678901234"
    expected_url = "https://brasilapi.com.br/api/cnpj/v1/12345678901234"
    assert build_url(cfg, cnpj) == expected_url

def test_build_url_with_existing_query_params():
    """Testa a construção de URL com parâmetros de query existentes."""
    cfg = ApiConfig(endpoint="https://api.example.com/cnpj?source=test")
    cnpj = "12345678901234"
    expected_url = "https://api.example.com/cnpj?source=test&cnpj=12345678901234"
    assert build_url(cfg, cnpj) == expected_url

def test_read_cnpjs_normalized_duplicate_not_invalid():
    """Testa que um CNPJ normalizado que é um duplicado não é marcado como inválido."""
    # CNPJ válido, um completo e outro abreviado que será normalizado para o mesmo.
    # O bug atual faz com que a linha "33.000.167/0001-01" seja considerada inválida.
    lines = ["33000167000101", "33.000.167/0001-01"]

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        for line in lines:
            tmp.write(line + "\n")
        tmp_path = tmp.name

    try:
        cnpjs, invalids, normalized_count = read_cnpjs(tmp_path)

        assert len(cnpjs) == 1
        assert cnpjs[0] == "33000167000101"
        assert not invalids
        assert normalized_count == 0  # A segunda linha é um duplicado, não uma nova normalização.

    finally:
        os.remove(tmp_path)
