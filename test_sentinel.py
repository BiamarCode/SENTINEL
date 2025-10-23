import pytest
from SENTINEL import build_url, ApiConfig

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
