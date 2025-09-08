# Ferramenta para ler e anonimizar dados PII de logs do watson assistant V1
# Autor: Sergio Gama
# Data: 04-Set-2025

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Anonimizador de logs do Watson Assistant V1 com watsonx.ai

- Busca /v1/workspaces/{workspace_id}/logs?version=2021-06-14 (com paginação)
- Pré-mascara PII conhecida (regex) para reduzir exposição
- Usa WatsonxLLM para anonimizar o que sobrar (nomes, endereços, RG etc.)
- Escreve JSONL com um log por linha no diretório corrente

Env vars esperadas:
    WA_URL, WA_APIKEY, WA_WORKSPACE_ID
    WATSONX_URL, WATSONX_APIKEY, WATSONX_PROJECT_ID
Model (opcional): WATSONX_MODEL_ID (ex: "ibm/granite-20b-multilingual")
"""

# Imports
import os
import re
import json
import time
import sys
import logging
from typing import Dict, Any, Generator, List, Optional
import requests
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse, parse_qs
import random
from dotenv import load_dotenv

# Configuração de ambiente e variáveis globais
load_dotenv()
API_VERSION = os.getenv("WA_VERSION", "2021-06-14")
WA_URL = os.getenv("WA_URL", "").rstrip("/")
WA_APIKEY = os.getenv("WA_APIKEY", "")
WA_WORKSPACE_ID = os.getenv("WA_WORKSPACE_ID", "")
WATSONX_URL = os.getenv("WATSONX_URL", "")
WATSONX_APIKEY = os.getenv("WATSONX_APIKEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_MODEL_ID = os.getenv("WATSONX_MODEL_ID", "meta-llama/llama-3-3-70b-instruct")
OUT_FILE = os.getenv("OUT_FILE", "watson_v1_logs_anon.json")
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "200"))
SLEEP_BETWEEN_PAGES = float(os.getenv("SLEEP_BETWEEN_PAGES", "0.25"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s | %(message)s",
    datefmt="%H:%M:%S"
)

# -------------------------- Luhn para cartões --------------------------
def luhn_ok(digits: str) -> bool:
    s = 0
    flip = False
    for ch in reversed(digits):
        if not ch.isdigit():
            return False
        d = int(ch)
        if flip:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        flip = not flip
    return s % 10 == 0

logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s | %(message)s",
        datefmt="%H:%M:%S"
)

def get_watsonx_token(api_key: str) -> str:
    """
    Gera o token Bearer usando a API Key do Watsonx via IBM Cloud IAM.

    """
    url = "https://iam.cloud.ibm.com/identity/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {
        "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
        "apikey": api_key
    }
    try:
        resp = requests.post(url, headers=headers, data=data)
        if resp.status_code != 200:
            raise Exception(f"Erro ao obter token IAM: {resp.text}")
        token = resp.json().get("access_token")
        if not token:
            raise Exception("Token não encontrado na resposta do IAM.")
        return token
    except Exception as e:
        logging.error(f"Falha ao obter token IAM: {e}")
        raise

# -------------------------- Pré-máscaras (regex) --------------------------

_re_email = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_re_cpf = re.compile(r"\b\d{3}\D?\d{3}\D?\d{3}\D?\d{2}\b")
# RG é variado; aqui um padrão comum (pode colidir com outros números longos)
_re_rg    = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b")
_re_phone = re.compile(r"(\+?\d{1,3}[\s\-\.]?)?(\(?\d{2,3}\)?[\s\-\.]?)?\d{4,5}[\s\-\.]?\d{4}\b")

# cartões (13–19 dígitos, tolera separadores), validando por Luhn
_re_card_candidate = re.compile(r"(?:\d[ -]?){13,19}")

# -------------------------- Log de dados sensíveis --------------------------
ORIG_LOG_FILE = os.getenv("ORIG_LOG_FILE", "watson_v1_logs_original.json")
SENSITIVE_KEYS = ["cpf", "rg", "email", "telefone", "cartao", "card", "documento", "doc"]

def cpf_is_valid(digits: str) -> bool:
    d = re.sub(r"\D", "", digits)
    if len(d) != 11 or d == d[0] * 11:
        return False
    # cálculo dos dígitos verificadores
    s = sum(int(d[i]) * (10 - i) for i in range(9))
    dv1 = (s * 10) % 11
    if dv1 == 10: dv1 = 0
    if dv1 != int(d[9]): return False
    s = sum(int(d[i]) * (11 - i) for i in range(10))
    dv2 = (s * 10) % 11
    if dv2 == 10: dv2 = 0
    return dv2 == int(d[10])

def mask_sensitive_value(key, value):
    if key.lower() == "cpf" and isinstance(value, str):
        return "[CPF]"
    if key.lower() == "rg" and isinstance(value, str):
        return "[RG]"
    if key.lower() == "email" and isinstance(value, str):
        return "[EMAIL]"
    if key.lower() in ["telefone", "phone"] and isinstance(value, str):
        return "[PHONE]"
    if key.lower() in ["cartao", "card"] and isinstance(value, str):
        return "[CARD]"
    if key.lower() in ["documento", "doc"] and isinstance(value, str):
        return "[DOC]"
    return value

def shuffle_string(s: str) -> str:
    """Embaralha os caracteres de uma string mantendo o mesmo tamanho."""
    chars = list(s)
    random.shuffle(chars)
    return ''.join(chars)
PRIV_LOG_FILE = os.getenv("PRIV_LOG_FILE", "watson_v1_logs_privados.jsonl")

def extract_sensitive(text: str) -> dict:
    """Extrai dados sensíveis encontrados no texto."""
    found = {}
    if not text:
        return found
    emails = _re_email.findall(text)
    if emails:
        found["emails"] = emails
    cpfs = _re_cpf.findall(text)
    if cpfs:
        found["cpfs"] = cpfs
    rgs = _re_rg.findall(text)
    if rgs:
        found["rgs"] = rgs
    phones = _re_phone.findall(text)
    if phones:
        found["phones"] = phones
    cards = []
    for m in _re_card_candidate.finditer(text):
        raw = re.sub(r"[^\d]", "", m.group(0))
        if 13 <= len(raw) <= 19 and luhn_ok(raw):
            cards.append(m.group(0))
    if cards:
        found["cards"] = cards
    return found

def log_sensitive(entry_id: Optional[str], text: str, found: dict, fh_priv):
    """Loga dados sensíveis encontrados."""
    if found and fh_priv:
        line = json.dumps({"entry_id": entry_id, "found": found, "text": text}, ensure_ascii=False)
        fh_priv.write(line + "\n")

def pre_mask(text: str, entry_id: Optional[str] = None, fh_priv=None) -> str:
    if not text:
        return text
    found = extract_sensitive(text)
    log_sensitive(entry_id, text, found, fh_priv)
    # e-mail
    def _mask_email(m: re.Match) -> str:
        return "[EMAIL]" + shuffle_string(m.group(0))
    text = _re_email.sub(_mask_email, text)
    # CPF (evita colidir com RG abaixo)
    def _mask_cpf(m: re.Match) -> str:
        return "[CPF]"
    text = _re_cpf.sub(_mask_cpf, text)
    # RG
    def _mask_rg(m: re.Match) -> str:
        return "[RG]" + shuffle_string(m.group(0))
    text = _re_rg.sub(_mask_rg, text)
    # Phone
    def _mask_phone(m: re.Match) -> str:
        return "[PHONE]" + shuffle_string(m.group(0))
    text = _re_phone.sub(_mask_phone, text)
    # Cartão: valida Luhn antes de mascarar
    def _mask_card(m: re.Match) -> str:
        raw = re.sub(r"[^\d]", "", m.group(0))
        if 13 <= len(raw) <= 19 and luhn_ok(raw):
            return "[CARD]" + shuffle_string(m.group(0))
        return m.group(0)
    text = _re_card_candidate.sub(_mask_card, text)
    return text

# ---------- 2) NER com Presidio (nome/endereço/org) ----------
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import SpacyNlpEngine

nlp_engine = SpacyNlpEngine(models={"pt": "pt_core_news_md"})
analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["pt","en"])

def presidio_detect(text: str) -> List[Dict]:
    results: List[RecognizerResult] = analyzer.analyze(text=text, language="pt")
    mapping = {
        "PERSON":"NAME","LOCATION":"ADDRESS","EMAIL_ADDRESS":"EMAIL","PHONE_NUMBER":"PHONE",
        "CREDIT_CARD":"CARD","IP_ADDRESS":"IP","ORGANIZATION":"COMPANY","NRP":"DOC"
    }
    out=[]
    for r in results:
        label = mapping.get(r.entity_type)
        if label:
            out.append({"type":label,"start":r.start,"end":r.end,"value":text[r.start:r.end],"conf":float(r.score),"src":"presidio"})
    return out

def anonymize_text_llm(text: str, entry_id: Optional[str] = None, fh_priv=None) -> str:
    if not text:
        return text
    masked = pre_mask(text, entry_id, fh_priv)
    import requests
    WATSONX_URL = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com/ml/v1/text/chat?version=2023-05-29")
    WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
    WATSONX_MODEL_ID = os.getenv("WATSONX_MODEL_ID", "meta-llama/llama-3-3-70b-instruct")
    WATSONX_APIKEY = os.getenv("WATSONX_APIKEY", "")
    token = get_watsonx_token(WATSONX_APIKEY)
    body = {
        "messages": [
            {
                "role": "system",
                "content": "Extraia dados pessoais e sensíveis do texto e traga em formato JSON.\n\nInclua apenas os campos que reconhecer, sem inventar, resumir ou modificar o texto. Não escreva nada além do JSON.\n"
            },
            {
                "role": "user",
                "content": masked
            }
        ],
        "project_id": WATSONX_PROJECT_ID,
        "model_id": WATSONX_MODEL_ID,
        "frequency_penalty": 0,
        "max_tokens": 200,
        "presence_penalty": 0,
        "temperature": 0,
        "top_p": 1,
        "top_k": 1
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    try:
        response = requests.post(WATSONX_URL, headers=headers, json=body)
        if response.status_code != 200:
            logging.warning(f"Watsonx API non-200 response: {response.text}")
            return masked
        data = response.json()
        # Extrai o conteúdo do assistant
        #logging.info(f"AQUI 3: Watsonx response data: {data}")
        assistant_msg = None
        for msg in data.get("choices", []):
            if msg.get("message", {}).get("role") == "assistant":
                assistant_msg = msg.get("message", {}).get("content", "")
                break
        if not assistant_msg:
            logging.warning(f"Watsonx API não retornou resposta do assistant: {data}")
            return masked
        # Tenta extrair JSON do assistant_msg
        import re as _re
        import json as _json
        match = _re.search(r'\{[\s\S]*\}', assistant_msg)
        if not match:
            logging.warning(f"Assistant não retornou JSON válido: {assistant_msg}")
            return masked
        try:
            sensitive = _json.loads(match.group(0))
        except Exception:
            logging.warning(f"Falha ao decodificar JSON do assistant: {assistant_msg}")
            return masked
        final = masked
        for k, v in sensitive.items():
            if isinstance(v, str) and v.strip():
                final = final.replace(v, f"[{k.upper()}]")
        return final
    except Exception as e:
        logging.warning(f"Falha na chamada Watsonx API para entry_id={entry_id}: {e}")
        return masked

# -------------------------- Walker nos campos-alvo --------------------------
# -------------------------- Busca de logs Watson Assistant V1 --------------------------
def fetch_logs_v1(wa_url: str, wa_apikey: str, wa_workspace_id: str, filter_expr: Optional[str] = None, page_limit: int = PAGE_LIMIT) -> Generator[Dict[str, Any], None, None]:
    """
    Busca logs do Watson Assistant V1 via API REST, com paginação.
    """
    url = f"{wa_url}/v1/workspaces/{wa_workspace_id}/logs"
    params = {
        "version": API_VERSION,
        "page_limit": page_limit
    }
    if filter_expr:
        params["filter"] = filter_expr
    auth = HTTPBasicAuth("apikey", wa_apikey)
    next_cursor = None
    while True:
        q = dict(params)
        if next_cursor:
            q["cursor"] = next_cursor
        try:
            r = requests.get(url, params=q, auth=auth, timeout=60)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logging.error(f"Erro ao buscar logs da API WA: {e}")
            break
        for item in data.get("logs", []):
            yield item
        # tenta extrair cursor/next_url
        pagination = data.get("pagination", {}) or {}
        next_url = pagination.get("next_url")
        next_cursor = pagination.get("next_cursor")
        if next_url and not next_cursor:
            # tenta ler cursor da next_url
            try:
                parsed = urlparse(next_url)
                qs = parse_qs(parsed.query)
                cur = qs.get("cursor", [None])[0]
                next_cursor = cur
            except Exception:
                next_cursor = None
        if not next_cursor:
            break
        time.sleep(SLEEP_BETWEEN_PAGES)

# -------------------------- Main --------------------------

def main():
    try:
        fh_orig = open(ORIG_LOG_FILE, "w", encoding="utf-8")
        logging.info(f"Arquivo de log original aberto: {ORIG_LOG_FILE}")
    except Exception as e:
        logging.warning(f"Não consegui abrir {ORIG_LOG_FILE} para escrita ({e}). Log original não será gravado.")
        fh_orig = None
    logging.info("Iniciando anonimização de logs do Watson Assistant V1…")
    assert WA_URL and WA_APIKEY and WA_WORKSPACE_ID, "Defina WA_URL, WA_APIKEY e WA_WORKSPACE_ID"
    # WatsonxLLM removido, não é mais necessário criar conexão

    wrote = 0
    failed_write = False
    try:
        fh = open(OUT_FILE, "w", encoding="utf-8")
        logging.info(f"Arquivo de saída aberto para escrita: {OUT_FILE}")
    except Exception as e:
        logging.warning(f"Não consegui abrir {OUT_FILE} para escrita ({e}). Vou imprimir no STDOUT.")
        fh = None
        failed_write = True
    try:
        fh_priv = open(PRIV_LOG_FILE, "w", encoding="utf-8")
        logging.info(f"Arquivo de log de dados sensíveis aberto: {PRIV_LOG_FILE}")
    except Exception as e:
        logging.warning(f"Não consegui abrir {PRIV_LOG_FILE} para escrita ({e}). Dados sensíveis não serão logados.")
        fh_priv = None

    filtro = None  # ex.: 'language::pt-br,request.timestamp>2025-08-20T00:00:00Z'
    logs_raw = []
    pagination = {}
    # 1. Busca todos os logs e salva o original como dict JSON
    logging.info("Buscando logs do Watson Assistant V1…")
    for log in fetch_logs_v1(WA_URL, WA_APIKEY, WA_WORKSPACE_ID, filter_expr=filtro):
        logs_raw.append(log)
    # Salva o original
    orig_obj = {
        "logs": logs_raw,
        "pagination": pagination
    }
    orig_json = json.dumps(orig_obj, ensure_ascii=False, indent=2)
    if fh_orig:
        fh_orig.write(orig_json)
        fh_orig.close()
        logging.info(f"✅ Log original salvo em ./{ORIG_LOG_FILE}")

    # 2. Processa cada campo text separadamente e monta a lista anon
    logs_anon = []
    wrote = 0
    for log in logs_raw:
        anon_log = json.loads(json.dumps(log))  # cópia fiel
        # request.input.text
        try:
            req_text = anon_log.get("request", {}).get("input", {}).get("text", "")
            if isinstance(req_text, str) and req_text:
                #logging.info(f"AQUI 1: Anonimizando log REQ_TEXT={req_text}")
                anon_text = anonymize_text_llm(req_text)
                #logging.info(f"AQUI 2: Anonimizado log ANON_TEXT={anon_text}")
                anon_log["request"]["input"]["text"] = anon_text
        except Exception as e:
            logging.warning(f"Erro ao anonimizar request.input.text: {e}")
        # response.output.generic[i].text onde response_type == 'text'
        try:
            generics = anon_log.get("response", {}).get("output", {}).get("generic", [])
            if isinstance(generics, list):
                for i, gen in enumerate(generics):
                    if isinstance(gen, dict) and gen.get("response_type") == "text":
                        text_val = gen.get("text", "")
                        if isinstance(text_val, str) and text_val:
                            anon_text = anonymize_text_llm(text_val)
                            anon_log["response"]["output"]["generic"][i]["text"] = anon_text
        except Exception as e:
            logging.warning(f"Erro ao anonimizar response.output.generic.text: {e}")

        # Procurar se existe um dos campos que sejam prováveis
        # dados sensíveis, como cpf, nome, endereço, cartão, etc
        # em request/context
        try:
            context = anon_log.get("request", {}).get("context", {})
            if isinstance(context, dict):
                for k, v in context.items():
                    if isinstance(v, str) and v:
                        lower_k = k.lower()
                        if any(sk in lower_k for sk in SENSITIVE_KEYS):
                            anon_text = pre_mask(v, None, fh_priv)
                            anon_log["request"]["context"][k] = anon_text
        except Exception as e:
            logging.warning(f"Erro ao anonimizar request.context: {e}")

        # Procurar se existe um dos campos que sejam prováveis
        # dados sensíveis, como cpf, nome, endereço, cartão, etc
        # em response/context
        try:
            context = anon_log.get("response", {}).get("context", {})
            if isinstance(context, dict):
                for k, v in context.items():
                    if isinstance(v, str) and v:
                        lower_k = k.lower()
                        if any(sk in lower_k for sk in SENSITIVE_KEYS):
                            anon_text = pre_mask(v, None, fh_priv)
                            anon_log["response"]["context"][k] = anon_text
        except Exception as e:
            logging.warning(f"Erro ao anonimizar response.context: {e}")

        # Procurar se existe um dos campos que sejam prováveis
        # dados sensíveis, como cpf, nome, endereço, cartão, etc
        # em request/context/history
        try:
            history = anon_log.get("request", {}).get("context", {}).get("history", {})
            if isinstance(history, dict):
                for k, v in history.items():
                    if isinstance(v, str) and v:
                        lower_k = k.lower()
                        if any(sk in lower_k for sk in SENSITIVE_KEYS):
                            anon_text = pre_mask(v, None, fh_priv)
                            anon_log["request"]["context"]["history"][k] = anon_text
        except Exception as e:
            logging.warning(f"Erro ao anonimizar request.context.history: {e}")

        # Procurar se existe um dos campos que sejam prováveis
        # dados sensíveis, como cpf, nome, endereço, cartão, etc
        # em response/context/history
        try:
            history = anon_log.get("response", {}).get("context", {}).get("history", {})
            if isinstance(history, dict):
                for k, v in history.items():
                    if isinstance(v, str) and v:
                        lower_k = k.lower()
                        if any(sk in lower_k for sk in SENSITIVE_KEYS):
                            anon_text = pre_mask(v, None, fh_priv)
                            anon_log["response"]["context"]["history"][k] = anon_text
        except Exception as e:
            logging.warning(f"Erro ao anonimizar response.context.history: {e}")

        logs_anon.append(anon_log)
        wrote += 1
        if wrote % 100 == 0:
            logging.info(f"{wrote} logs anonimizados…")

    # Salva todos os logs anonimizados em um único JSON
    output_obj = {
        "logs": logs_anon,
        "pagination": pagination
    }
    output_json = json.dumps(output_obj, ensure_ascii=False, indent=2)
    if fh:
        fh.write(output_json)
        fh.close()
        logging.info(f"✅ Concluído. {wrote} logs ANONIMIZADOS salvos em ./{OUT_FILE}")
    elif failed_write:
        print(output_json)
        logging.info("✅ Concluído. Logs anonimizados foram emitidos no STDOUT.")
    if 'fh_priv' in locals() and fh_priv:
        fh_priv.close()
        logging.info(f"✅ Log de dados sensíveis salvo em ./{PRIV_LOG_FILE}")

if __name__ == "__main__":
    print("Iniciando anonimização de logs do Watson Assistant V1…")
    main()

