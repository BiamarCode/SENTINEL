# SENTINEL

O SENTINEL é uma ferramenta de linha de comando desenvolvida em Python para verificar o status de Cadastro Nacional da Pessoa Jurídica (CNPJ) na Receita Federal do Brasil. A ferramenta utiliza a [BrasilAPI](https://brasilapi.com.br/) como fonte de dados padrão, mas é compatível com outros provedores de API.

## Funcionalidades

- **Consulta em Lote:** Verifique múltiplos CNPJs a partir de um arquivo de texto.
- **Validação de CNPJ:** Garante que apenas CNPJs com formato válido sejam consultados.
- **Relatórios Detalhados:** Gera um arquivo CSV com o resultado detalhado de cada consulta.
- **Saída Simplificada:** Cria um arquivo de texto contendo apenas os CNPJs com status "baixado".
- **Controle de Taxa de Requisições:** Evita o bloqueio da API controlando o número de requisições por segundo.
- **Flexibilidade de API:** Permite a configuração de diferentes endpoints e credenciais de API através de variáveis de ambiente ou argumentos de linha de comando.

## Instalação

1.  **Clone o repositório:**
    ```bash
    git clone https://github.com/seu-usuario/sentinel.git
    cd sentinel
    ```

2.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```

## Uso

1.  **Crie um arquivo `cnpjs.txt`** na raiz do projeto, com um CNPJ por linha.

2.  **Execute o script:**
    ```bash
    python SENTINEL.py
    ```

### Argumentos de Linha de Comando

| Argumento | Descrição | Padrão |
| --- | --- | --- |
| `--input` | Arquivo de entrada com CNPJs. | `cnpjs.txt` |
| `--baixados-out` | Arquivo de saída para CNPJs baixados. | `baixados_na_receita.txt` |
| `--relatorio-out` | Arquivo de relatório em CSV. | `relatorio.csv` |
| `--rate` | Requisições por segundo. | `1.5` |
| `--timeout` | Timeout por requisição em segundos. | `20` |
| `--log-level` | Nível de log (DEBUG, INFO, WARNING, ERROR).| `INFO` |
| `--verbose` | Exibe logs detalhados por CNPJ. | `False` |
| `--input-encoding`| Encoding do arquivo de entrada. | `utf-8` |
| `--output-encoding`| Encoding dos arquivos de saída. | `utf-8` |
| `--endpoint` | URL da API para consulta. | `https://brasilapi.com.br/api/cnpj/v1` |
| `--version` | Mostra a versão e sai. | |

### Configuração via Variáveis de Ambiente

É possível configurar a API através das seguintes variáveis de ambiente:

- `API_BR_ENDPOINT`
- `API_BR_API_KEY`
- `API_BR_AUTH_HEADER`
- `API_BR_AUTH_SCHEME`
- `API_BR_CNPJ_PARAM_NAME`
- `API_TIMEOUT_SEC`

## Desenvolvimento

Para contribuir com o desenvolvimento, siga os passos de instalação e crie um *pull request* com suas alterações.

## Licença

Este projeto está licenciado sob a Licença MIT.
