# SENTINEL

O **SENTINEL** é uma ferramenta de linha de comando desenvolvida em Python para verificar em lote o status de múltiplos Cadastros Nacionais da Pessoa Jurídica (CNPJ) na Receita Federal do Brasil.

A ferramenta utiliza a [BrasilAPI](https://brasilapi.com.br/) como fonte de dados padrão, que não requer chave de acesso, mas é compatível com outros provedores de API que podem exigir autenticação.

## Funcionalidades Principais

-   **Consulta em Lote:** Verifique uma lista de CNPJs a partir de um arquivo de texto.
-   **Validação de CNPJ:** Garante que apenas CNPJs com formato válido sejam consultados, ignorando entradas inválidas.
-   **Relatórios Detalhados:** Gera um arquivo CSV (`relatorio.csv`) com o resultado detalhado de cada consulta, incluindo status HTTP e mensagens de erro.
-   **Saída Simplificada:** Cria um arquivo de texto (`baixados_na_receita.txt`) contendo apenas os CNPJs com status "baixado".
-   **Controle de Taxa de Requisições:** Evita o bloqueio da API, controlando o número de requisições por segundo.
-   **Flexibilidade de API:** Permite a configuração de diferentes endpoints e credenciais de API através de variáveis de ambiente ou argumentos de linha de comando.
-   **Retentativas Automáticas:** Tenta novamente em caso de erros de rede ou de servidor (HTTP 5xx).

## Instalação

1.  **Clone o repositório:**
    ```bash
    git clone https://github.com/seu-usuario/sentinel.git
    cd sentinel
    ```

2.  **Crie e ative um ambiente virtual (recomendado):**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    # No Windows, use: .venv\Scripts\activate
    ```

3.  **Instale as dependências a partir de `requirements.txt`:**
    ```bash
    pip install -r requirements.txt
    ```

## Como Usar

### 1. Prepare o Arquivo de Entrada

Crie um arquivo chamado `cnpjs.txt` (ou qualquer outro nome que preferir) na raiz do projeto. Adicione um CNPJ por linha. O arquivo pode conter CNPJs formatados ou apenas com dígitos.

**Exemplo de `cnpjs.txt`:**

```
33.000.167/0001-01
00000000000191
12345678000195
```

### 2. Execute o Script

No seu terminal, execute o seguinte comando:

```bash
python3 SENTINEL.py --input cnpjs.txt
```

O script irá processar os CNPJs e gerar dois arquivos de saída.

### 3. Analise os Resultados

Após a execução, os seguintes arquivos serão criados ou atualizados:

-   **`baixados_na_receita.txt`**: Contém apenas os CNPJs que foram identificados com o status "baixado".

    ```
    33000167000101
    ```

-   **`relatorio.csv`**: Um relatório detalhado de cada CNPJ consultado.

    | cnpj | status | codigo_situacao | descricao_situacao | raw_status | http_status | error |
    | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
    | 33000167000101 | baixado | 04 | BAIXADA | 04 \| BAIXADA | 200 | |
    | 00000000000191 | nao_baixado | 02 | ATIVA | 02 \| ATIVA | 200 | |
    | 12345678000195 | erro_api | | | \<indefinido\> | 404 | HTTP 404 |

## Argumentos de Linha de Comando

| Argumento | Descrição | Padrão |
| --- | --- | --- |
| `--input` | Arquivo de entrada com CNPJs. | `cnpjs.txt` |
| `--baixados-out`| Arquivo de saída para CNPJs baixados. | `baixados_na_receita.txt` |
| `--relatorio-out`| Arquivo de relatório em CSV. | `relatorio.csv` |
| `--rate` | Requisições por segundo. | `1.5` |
| `--timeout` | Timeout por requisição em segundos. | `20` |
| `--log-level` | Nível de log (DEBUG, INFO, WARNING, ERROR).| `INFO` |
| `--verbose` | Exibe logs detalhados por CNPJ no console. | `False` |
| `--input-encoding`| Encoding do arquivo de entrada. | `utf-8` |
| `--output-encoding`| Encoding dos arquivos de saída. | `utf-8` |
| `--endpoint` | URL da API para consulta. | `https://brasilapi.com.br/api/cnpj/v1` |
| `--version` | Mostra a versão do programa e sai. | |

## Configuração Avançada (API)

Para usar um provedor de API diferente da BrasilAPI, você pode configurar o endpoint e as credenciais através de variáveis de ambiente.

-   `API_BR_ENDPOINT`: URL base da API (ex: `https://api.suaempresa.com/v2/cnpj`).
-   `API_BR_API_KEY`: Sua chave de API.
-   `API_BR_AUTH_HEADER`: Cabeçalho de autenticação (padrão: `Authorization`).
-   `API_BR_AUTH_SCHEME`: Esquema de autenticação (padrão: `Bearer`).
-   `API_BR_CNPJ_PARAM_NAME`: Nome do parâmetro do CNPJ se a API o espera na query string (padrão: `cnpj`).
-   `API_TIMEOUT_SEC`: Timeout global para as requisições.

## Desenvolvimento

Para contribuir com o desenvolvimento, siga os passos de instalação, crie uma nova branch e envie um *pull request* com suas alterações.

### Testes

Os testes são escritos com `pytest`. Para executá-los, instale as dependências de desenvolvimento e rode o comando:

```bash
pip install pytest
python3 -m pytest
```

## Licença

Este projeto está licenciado sob a Licença MIT.
