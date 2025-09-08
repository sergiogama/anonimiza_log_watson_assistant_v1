# Watson Assistant V1 Log Anonymizer

Este projeto é um script Python para anonimização de logs do Watson Assistant V1, utilizando regex e LLM (watsonx.ai) para mascarar dados sensíveis, como CPF, RG, e-mail, telefone e cartão.

## Funcionalidades
- Busca logs do Watson Assistant V1 via API REST (com paginação)
- Pré-mascara PII conhecida (regex)
- Usa LLM (watsonx.ai) para anonimizar nomes, endereços, RG, etc.
- Gera arquivos de auditoria e logs anonimizados
- Estrutura de saída: JSON único com lista de logs

## Instalação

```sh
# Clone o repositório
$ git clone https://github.com/seuusuario/watson-assistant-log-anonymizer.git
$ cd watson-assistant-log-anonymizer

# Execute o setup
$ bash setup.sh
```

## Configuração
Crie um arquivo `.env` com as seguintes variáveis (exemplo em `.env.exemplo`):

```
WA_URL=https://api.us-south.assistant.watson.cloud.ibm.com
WA_APIKEY=seu_apikey_wa
WA_WORKSPACE_ID=seu_workspace_id
WATSONX_URL=https://us-south.ml.cloud.ibm.com/ml/v1/text/chat?version=2023-05-29
WATSONX_APIKEY=seu_apikey_watsonx
WATSONX_PROJECT_ID=seu_project_id
WATSONX_MODEL_ID=ibm/granite-20b-multilingual
```

## Uso

```sh
$ python ler_logs_wa.py
```

Os arquivos de saída serão gerados no diretório corrente:
- `watson_v1_logs_anon.json` — logs anonimizados
- `watson_v1_logs_original.json` — logs originais
- `watson_v1_logs_privados.jsonl` — dados sensíveis encontrados

## Testes

Se houver testes automatizados:
```sh
$ pytest -q
```

## Boas práticas
- Nunca suba arquivos `.env` ou de credenciais para o repositório
- Use o `.gitignore` fornecido
- Documente alterações relevantes no README

## Licença
MIT

---

> Projeto desenvolvido por Sergio Gama
