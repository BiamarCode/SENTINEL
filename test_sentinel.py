import pytest
import os
import tempfile
import csv
from unittest.mock import patch, MagicMock
from SENTINEL import (
    build_url,
    ApiConfig,
    read_cnpjs,
    validate_cnpj_digits,
    decode_status,
    main,
    StatusInfo
)

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

@pytest.mark.parametrize("cnpj, expected", [
    ("33.000.167/0001-01", True),
    ("33000167000101", True),
    ("11.111.111/1111-11", False),
    ("12345", False),
    ("11111111111111", False),
    (None, False),
    ("", False),
])
def test_validate_cnpj_digits(cnpj, expected):
    """Testa a validação de CNPJ com diferentes formatos e casos de borda."""
    assert validate_cnpj_digits(cnpj) == expected

def test_read_cnpjs_empty_file():
    """Testa o comportamento de read_cnpjs com um arquivo de entrada vazio."""
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        tmp_path = tmp.name

    try:
        cnpjs, invalids, normalized_count = read_cnpjs(tmp_path)
        assert cnpjs == []
        assert invalids == []
        assert normalized_count == 0
    finally:
        os.remove(tmp_path)

@pytest.mark.parametrize("payload, expected_is_baixado, expected_raw_status_part", [
    ({"codigo_situacao_cadastral": "04"}, True, "04"),
    ({"descricao_situacao_cadastral": "BAIXADA"}, True, "BAIXADA"),
    ({"empresa": {"situacao_cadastral": "BAIXADA"}}, True, "BAIXADA"),
    ({"descricao_situacao_cadastral": "ATIVA"}, False, "ATIVA"),
    ({"status": "Situação: Baixada"}, True, "Situação: Baixada"),
    ({}, False, "<indefinido>"),
    ({"codigo_situacao_cadastral": 2}, False, "2"),
    ({"status": "ATIVA", "dados": {"situacao": "BAIXA DEFINITIVA"}}, True, "BAIXA DEFINITIVA"),
])
def test_decode_status(payload, expected_is_baixado, expected_raw_status_part):
    """Testa a decodificação de status com vários formatos de payload."""
    status_info = decode_status(payload)
    assert status_info.is_baixado == expected_is_baixado
    assert expected_raw_status_part in status_info.raw_status

@patch('SENTINEL.safe_request')
def test_main_integration(mock_safe_request):
    """Testa o fluxo principal de ponta a ponta com mocks."""

    def mock_request_side_effect(session, url, headers, timeout):
        if "33000167000101" in url:
            return 200, {"descricao_situacao_cadastral": "BAIXADA"}, None
        elif "00000000000191" in url:
            return 200, {"descricao_situacao_cadastral": "ATIVA"}, None
        return 404, None, "Not Found"

    mock_safe_request.side_effect = mock_request_side_effect

    cnpjs_to_test = ["33000167000101", "00000000000191", "12345678000195"]

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, "cnpjs.txt")
        baixados_path = os.path.join(tmpdir, "baixados.txt")
        relatorio_path = os.path.join(tmpdir, "relatorio.csv")

        with open(input_path, "w", encoding="utf-8") as f:
            for cnpj in cnpjs_to_test:
                f.write(cnpj + "\n")

        argv = [
            "--input", input_path,
            "--baixados-out", baixados_path,
            "--relatorio-out", relatorio_path,
            "--rate", "1000",
        ]

        return_code = main(argv)
        assert return_code == 0

        with open(baixados_path, "r", encoding="utf-8") as f:
            baixados_content = f.read().strip().splitlines()
        assert baixados_content == ["33000167000101"]

        with open(relatorio_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["cnpj"] == "33000167000101"
        assert rows[0]["status"] == "baixado"
        assert rows[1]["cnpj"] == "00000000000191"
        assert rows[1]["status"] == "nao_baixado"
        assert rows[2]["cnpj"] == "12345678000195"
        assert rows[2]["status"] == "erro_api"
        assert rows[2]["http_status"] == "404"

def test_read_cnpjs_all_invalid():
    """Testa o comportamento de read_cnpjs com um arquivo contendo apenas CNPJs inválidos."""
    invalid_lines = ["123", "abc", "11.111.111/1111-11"]
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        for line in invalid_lines:
            tmp.write(line + "\n")
        tmp_path = tmp.name

    try:
        cnpjs, invalids, normalized_count = read_cnpjs(tmp_path)
        assert cnpjs == []
        assert invalids == invalid_lines
        assert normalized_count == 0
    finally:
        os.remove(tmp_path)
