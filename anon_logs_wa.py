# Autor: Sergio Gama
# Data: 07-09-2025
# Descrição: Script de anonimização de logs do Watson Assistant V1

# ENV úteis:
#  USE_HF_NER=true|false          # liga/desliga HuggingFace
#  HF_NER_MODEL=...               # modelo (default Babelscape/wikineural-multilingual-ner)
#  HF_DEVICE=-1|0|1               # -1=CPU, 0 ou 1=GPU


"""
Anonimizador simples de logs do Watson Assistant V1

- Busca /v1/workspaces/{workspace_id}/logs?version=2021-06-14
- Anonimiza PII via regex (CPF com validação, CNPJ, EMAIL, PHONE, CEP, CARTÃO c/ Luhn)
- NER via HuggingFace (PER/LOC/ORG) + heurística de endereço (expande número)
- Salva original, anonimizado e um .jsonl com os spans encontrados
"""

import os, re, json, time, logging, requests
from typing import Dict, Any, Generator, List, Optional
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv
# topo do arquivo — substitua a linha `import phonenumbers` por:
try:
    import phonenumbers  # type: ignore
    HAS_PHONENUMBERS = True
except Exception:
    phonenumbers = None  # type: ignore
    HAS_PHONENUMBERS = False


# -------------------- Config --------------------
load_dotenv()
API_VERSION   = os.getenv("WA_VERSION", "2021-06-14")
WA_URL        = (os.getenv("WA_URL") or "").rstrip("/")
WA_APIKEY     = os.getenv("WA_APIKEY", "")
WA_WORKSPACE  = os.getenv("WA_WORKSPACE_ID", "")
OUT_FILE      = os.getenv("OUT_FILE", "watson_v1_logs_anon.json")
ORIG_FILE     = os.getenv("ORIG_LOG_FILE", "watson_v1_logs_original.json")
PRIV_FILE     = os.getenv("PRIV_LOG_FILE", "watson_v1_logs_privados.jsonl")
PAGE_LIMIT    = int(os.getenv("PAGE_LIMIT", "200"))

# --- HF NER ---
USE_HF_NER    = (os.getenv("USE_HF_NER", "true").lower() in {"1","true","yes","y"})
HF_NER_MODEL  = os.getenv("HF_NER_MODEL", "Babelscape/wikineural-multilingual-ner")  # bom para PT
HF_DEVICE     = int(os.getenv("HF_DEVICE", "-1"))  # -1 CPU, 0 GPU0, etc.

_hf_ner_pipe = None

def _ensure_hf_pipeline():
    """Inicializa uma única vez a pipeline HF de NER."""
    global _hf_ner_pipe
    if not USE_HF_NER:
        return None
    if _hf_ner_pipe is not None:
        return _hf_ner_pipe
    try:
        from transformers import pipeline
        _hf_ner_pipe = pipeline(
            task="token-classification",
            model=HF_NER_MODEL,
            aggregation_strategy="simple",
            device=HF_DEVICE
        )
        logging.info(f"HF NER carregado: {HF_NER_MODEL} (device={HF_DEVICE})")
    except Exception as e:
        logging.warning(f"Falha ao carregar HF NER ({e}). Prosseguindo sem HF NER.")
        _hf_ner_pipe = None
    return _hf_ner_pipe

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s | %(message)s",
    datefmt="%H:%M:%S"
)

# -------------------- Util Luhn --------------------
def luhn_ok(s: str) -> bool:
    s = re.sub(r"\D", "", s)
    d, alt = 0, False
    for ch in reversed(s):
        n = int(ch)
        if alt:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        d += n
        alt = not alt
    return (13 <= len(s) <= 19) and (d % 10 == 0)

# -------------------- CPF válido --------------------
def cpf_is_valid(digits: str) -> bool:
    d = re.sub(r"\D", "", digits)
    if len(d) != 11 or d == d[0] * 11:
        return False
    s = sum(int(d[i]) * (10 - i) for i in range(9))
    dv1 = (s * 10) % 11
    if dv1 == 10: dv1 = 0
    if dv1 != int(d[9]): return False
    s = sum(int(d[i]) * (11 - i) for i in range(10))
    dv2 = (s * 10) % 11
    if dv2 == 10: dv2 = 0
    return dv2 == int(d[10])

# -------------------- Regex --------------------
RE_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
RE_CPF   = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
RE_CNPJ  = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")
RE_RG    = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b")
RE_CARD  = re.compile(r"(?:\d[ -]?){13,19}")
RE_CEP   = re.compile(r"\b\d{5}-?\d{3}\b")

# Palavras-chave fortes de endereço (independente de NER)
_ADDR_KEYS = r"(?:rua|r\.|av\.?|avenida|alameda|travessa|tv\.?|estrada|rodovia|rod\.?|praça|praca|largo|lgo\.?|quadra|qd\.?|lote|lt\.?)"
ADDR_RE = re.compile(rf"(?i)\b{_ADDR_KEYS}\s+[^\n,.]{{1,120}}")  # era {2,120}

# Expansão do final do endereço para incluir ", 131", " nº 131", etc.
_ADDR_RIGHT = re.compile(r"""^[\s,;-]*(?:n[ºo]\s*)?\d{1,6}(?:\s*[A-Za-zº°/\-]\w{0,10})?""", re.X)

LABELS = {
    "NAME":"[NAME]","ADDRESS":"[ADDRESS]","COMPANY":"[COMPANY]",
    "EMAIL":"[EMAIL]","PHONE":"[PHONE]","CPF":"[CPF]","CNPJ":"[CNPJ]",
    "RG":"[RG]","DOC":"[DOC]","CARD":"[CARD]","DOB":"[DOB]","IP":"[IP]","CEP":"[CEP]"
}

def _add_span(collector, start, end, typ):
    if start is None or end is None or end <= start:
        return
    collector.append({"start": int(start), "end": int(end), "type": typ})

def _expand_address_right(text: str, start: int, end: int) -> int:
    tail = text[end:]
    m = _ADDR_RIGHT.match(tail)
    if m:
        return end + m.end()
    return end

def keyword_address_spans(text: str) -> List[Dict]:
    spans = []
    for m in ADDR_RE.finditer(text):
        s, e = m.start(), m.end()
        spans.append({"start": s, "end": e, "type": "ADDRESS"})
    return spans

def hf_pii_spans(text: str) -> List[Dict]:
    """
    Usa HF NER (PER/LOC/ORG…) e converte para NAME/ADDRESS/COMPANY.
    """
    pipe = _ensure_hf_pipeline()
    if pipe is None or not isinstance(text, str) or not text.strip():
        return []
    out = []
    try:
        preds = pipe(text)
        for p in preds:
            ent = (p.get("entity_group") or p.get("entity") or "").upper()
            s   = int(p["start"]); e = int(p["end"])
            if ent in {"PER","PERSON"}:
                out.append({"start": s, "end": e, "type": "NAME"})
            elif ent in {"LOC","GPE","FAC","LOCATION"}:
                out.append({"start": s, "end": e, "type": "ADDRESS"})
            elif ent in {"ORG","ORGANIZATION"}:
                out.append({"start": s, "end": e, "type": "COMPANY"})
            else:
                # MISC etc. ignoramos
                pass
    except Exception as e:
        logging.debug(f"HF NER falhou: {e}")
    return out

# Regex BR de telefone (fallback “aceita-tudo” razoável)
BR_PHONE_RE = re.compile(
    r"""(?xi)
    (?:                             # DUAS FORMAS:
        # (A) Com separador visível entre os blocos (4/5 + 4)
        (?:\+?55\s*)?               # DDI opcional
        (?:\(?\d{2}\)?\s*)?         # DDD opcional
        (?:9?\d{4}[-\s]\d{4})       # <---- separador OBRIGATÓRIO

      | # ou

        # (B) Compacto, só se tiver DDI+DDD
        \+?55\s*\d{2}\s*9?\d{4}\s*\d{4}
    )
    """
)

def detect_pii_spans(text: str) -> List[Dict]:
    if not isinstance(text, str) or not text:
        return []
    spans: List[Dict] = []

    # 1) Determinístico (regex)
    for m in RE_EMAIL.finditer(text):
        _add_span(spans, m.start(), m.end(), "EMAIL")

    for m in RE_CPF.finditer(text):
        raw = re.sub(r"\D", "", m.group())
        if cpf_is_valid(raw):
            _add_span(spans, m.start(), m.end(), "CPF")

    for m in re.finditer(r"[0-9.\-]{11,20}", text):
        raw = re.sub(r"\D", "", m.group())
        if len(raw) == 11 and cpf_is_valid(raw):
            _add_span(spans, m.start(), m.end(), "CPF")

    for m in re.finditer(r"(?i)\bCPF\b[^\d]{0,8}((?:\d[.\- ]?){8,24})", text):
        g = m.group(1) or ""
        s = m.start(1); e = s + len(g)
        _add_span(spans, s, e, "CPF")

    for m in re.finditer(r"(?<!\d)\d{11}(?!\d)", text):
        _add_span(spans, m.start(), m.end(), "CPF")

    for m in RE_CNPJ.finditer(text):
        _add_span(spans, m.start(), m.end(), "CNPJ")
    for m in RE_RG.finditer(text):
        _add_span(spans, m.start(), m.end(), "RG")
    for m in RE_CEP.finditer(text):
        _add_span(spans, m.start(), m.end(), "CEP")
    for m in RE_CARD.finditer(text):
        if luhn_ok(m.group()):
            _add_span(spans, m.start(), m.end(), "CARD")

    # PHONE (fallback regex — cobre os formatos dos testes)
    for m in BR_PHONE_RE.finditer(text):
        _add_span(spans, m.start(), m.end(), "PHONE")

    # PHONE (phonenumbers) — só se a lib estiver instalada
    if HAS_PHONENUMBERS:
        for m in re.finditer(r"\+?[\d\(\)\-\.\s]{8,}", text):
            try:
                num = phonenumbers.parse(m.group(), "BR")
                if phonenumbers.is_possible_number(num) and phonenumbers.is_valid_number(num):
                    _add_span(spans, m.start(), m.end(), "PHONE")
            except Exception:
                pass

    # 2) NER (HF) — NAME/ADDRESS/COMPANY
    spans.extend(hf_pii_spans(text))

    # 3) Endereço por palavras-chave (complemento independente de NER)
    spans.extend(keyword_address_spans(text))

    if not spans:
        return []
    
    # 3.5) Remove falsos-positivos de ADDRESS muito curtos (ex.: NER pegando "e", "fon" etc.)
    spans = [
        s for s in spans
        if not (s["type"] == "ADDRESS" and (s["end"] - s["start"] < 4))
    ]

    # 3.6) Se PHONE sobrepõe documentos, remova o PHONE (CPF/CNPJ/RG/CARD dominam)
    protected_types = {"CPF", "CNPJ", "RG", "CARD"}
    protected_ranges = [(s["start"], s["end"]) for s in spans if s["type"] in protected_types]

    def _overlaps(a, b):
        return not (a[1] <= b[0] or b[1] <= a[0])

    spans = [
        s for s in spans
        if not (s["type"] == "PHONE" and any(_overlaps((s["start"], s["end"]), pr) for pr in protected_ranges))
    ]

    # --- FUSÃO: absorver NAME/COMPANY vizinho em ADDRESS (antes de expandir número)
    spans.sort(key=lambda s: (s["start"], s["end"]))
    fused = []
    i = 0
    while i < len(spans):
        cur = spans[i]
        if cur["type"] == "ADDRESS":
            j = i + 1
            while j < len(spans):
                nxt = spans[j]
                # se NAME/COMPANY colado (gap <= 1) ou sobreposto, absorve no ADDRESS
                if nxt["type"] in {"NAME", "COMPANY"} and (nxt["start"] - cur["end"] <= 1 or nxt["start"] < cur["end"]):
                    cur["end"] = max(cur["end"], nxt["end"])
                    j += 1
                else:
                    break
            fused.append(cur)
            i = j
        else:
            fused.append(cur)
            i += 1
    spans = fused

    # --- Expansão do número após termos um bloco ADDRESS sólido
    for s in spans:
        if s["type"] == "ADDRESS":
            s["end"] = _expand_address_right(text, s["start"], s["end"])

    # --- RESOLUÇÃO DE OVERLAP
    # Regra geral:
    # - PHONE sempre preservado (não é cortado nem absorvido)
    # - ADDRESS domina NAME/COMPANY (absorve e unifica)
    # - Nos demais casos, corta o anterior na borda do próximo
    spans.sort(key=lambda s: (s["start"], s["end"]))
    resolved = []
    for s in spans:
        if not resolved:
            resolved.append(s); continue
        prev = resolved[-1]
        if s["start"] < prev["end"]:
            if prev["type"] == s["type"]:
                prev["end"] = max(prev["end"], s["end"])
            else:
                pair = {prev["type"], s["type"]}

                # (A) PHONE sempre preservado
                if "PHONE" in pair:
                    if prev["type"] == "PHONE":
                        # Aparar o começo de s para não invadir o PHONE
                        s["start"] = max(s["start"], prev["end"])
                        if s["end"] > s["start"]:
                            resolved.append(s)
                        # se ficou vazio, ignora s
                    else:
                        # s é PHONE → aparar o fim de prev
                        prev["end"] = min(prev["end"], s["start"])
                        if prev["end"] <= prev["start"]:
                            resolved.pop()
                        resolved.append(s)
                    continue

                # (B) ADDRESS domina NAME/COMPANY (unifica como ADDRESS)
                if "ADDRESS" in pair and ({"NAME","COMPANY"} & pair):
                    a_start = min(prev["start"], s["start"])
                    a_end   = max(prev["end"], s["end"])
                    if prev["type"] == "ADDRESS":
                        prev["start"], prev["end"] = a_start, a_end
                    else:
                        resolved.pop()
                        s["start"], s["end"] = a_start, a_end
                        s["type"] = "ADDRESS"
                        resolved.append(s)
                else:
                    # (C) demais pares → corta o anterior na borda do próximo
                    prev["end"] = min(prev["end"], s["start"])
                    if prev["end"] <= prev["start"]:
                        resolved.pop()
                    resolved.append(s)
        else:
            resolved.append(s)

    # limpa spans vazios
    filtered = [x for x in resolved if x["end"] > x["start"]]
    return filtered

def mask_with_spans(text: str, spans: List[Dict]) -> str:
    if not spans:
        return text
    out = text
    for s in sorted(spans, key=lambda x: x["start"], reverse=True):
        out = out[:s["start"]] + LABELS.get(s["type"], "[PII]") + out[s["end"]:]
    return out

def _priv_write(fh, path: str, original: str, spans: List[Dict]):
    if not fh or not spans:
        return
    fh.write(json.dumps({
        "path": path,
        "spans": spans,
        "original_preview": original[:200],
        "masked_preview": mask_with_spans(original, spans)[:200]
    }, ensure_ascii=False) + "\n")

# -------------------- Fetch logs WA V1 --------------------
def fetch_logs_v1(wa_url: str, wa_apikey: str, wa_workspace_id: str,
                  page_limit: int = PAGE_LIMIT, filter_expr: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
    url    = f"{wa_url}/v1/workspaces/{wa_workspace_id}/logs"
    params = {"version": API_VERSION, "page_limit": page_limit}
    if filter_expr:
        params["filter"] = filter_expr
    auth = HTTPBasicAuth("apikey", wa_apikey)
    cursor = None
    while True:
        q = dict(params)
        if cursor:
            q["cursor"] = cursor
        r = requests.get(url, params=q, auth=auth, timeout=60)
        r.raise_for_status()
        data = r.json()
        for item in data.get("logs", []) or []:
            yield item
        pag = data.get("pagination", {}) or {}
        cursor = pag.get("next_cursor")
        if not cursor:
            nxt = pag.get("next_url")
            if not nxt:
                break
            parsed = urlparse(nxt)
            qs = parse_qs(parsed.query)
            cursor = qs.get("cursor", [None])[0]
            if not cursor:
                break
        time.sleep(0.1)

# -------------------- Main --------------------
def main():
    assert WA_URL and WA_APIKEY and WA_WORKSPACE, "Defina WA_URL, WA_APIKEY e WA_WORKSPACE_ID"
    logging.info("Buscando logs…")
    logs_raw = list(fetch_logs_v1(WA_URL, WA_APIKEY, WA_WORKSPACE))
    logging.info(f"Total de logs: {len(logs_raw)}")

    # salva original
    with open(ORIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"logs": logs_raw, "pagination": {}}, f, ensure_ascii=False, indent=2)
    logging.info(f"Original salvo em ./{ORIG_FILE}")

    # abre o .jsonl de achados
    try:
        fh_priv = open(PRIV_FILE, "w", encoding="utf-8", newline="\n")
    except Exception as e:
        logging.warning(f"Não consegui abrir {PRIV_FILE} para escrita ({e}).")
        fh_priv = None

    # anonimiza (somente campos de texto relevantes)
    logs_anon: List[Dict[str, Any]] = []
    for log in logs_raw:
        anon = json.loads(json.dumps(log))  # deep copy simples

        # request.input.text
        req_text = (((anon.get("request") or {}).get("input") or {}).get("text") or "")
        if isinstance(req_text, str) and req_text.strip():
            spans = detect_pii_spans(req_text)
            if spans:
                _priv_write(fh_priv, "request.input.text", req_text, spans)
                anon["request"]["input"]["text"] = mask_with_spans(req_text, spans)

        # --- response.input.text (alguns logs espelham o input aqui) ---
        resp_in_text = (((anon.get("response") or {}).get("input") or {}).get("text") or "")
        if isinstance(resp_in_text, str) and resp_in_text.strip():
            spans = detect_pii_spans(resp_in_text)
            if spans:
                _priv_write(fh_priv, "response.input.text", resp_in_text, spans)
                # garante que os dicts existem
                anon.setdefault("response", {}).setdefault("input", {})["text"] = mask_with_spans(resp_in_text, spans)


        # response.output.text (string OU lista)
        out_texts = (((anon.get("response") or {}).get("output") or {}).get("text") or [])
        if isinstance(out_texts, list):
            new_texts = []
            for i, t in enumerate(out_texts):
                if isinstance(t, str) and t.strip():
                    spans = detect_pii_spans(t)
                    if spans:
                        _priv_write(fh_priv, f"response.output.text[{i}]", t, spans)
                        t = mask_with_spans(t, spans)
                new_texts.append(t)
            if "response" in anon and "output" in anon["response"]:
                anon["response"]["output"]["text"] = new_texts
        elif isinstance(out_texts, str) and out_texts.strip():
            t = out_texts
            spans = detect_pii_spans(t)
            if spans:
                _priv_write(fh_priv, "response.output.text", t, spans)
                if "response" in anon and "output" in anon["response"]:
                    anon["response"]["output"]["text"] = mask_with_spans(t, spans)

        # response.output.generic[].text
        generics = (((anon.get("response") or {}).get("output") or {}).get("generic") or [])
        if isinstance(generics, list):
            for i, gen in enumerate(generics):
                if isinstance(gen, dict) and gen.get("response_type") == "text":
                    t = gen.get("text", "")
                    if isinstance(t, str) and t.strip():
                        spans = detect_pii_spans(t)
                        if spans:
                            _priv_write(fh_priv, f"response.output.generic[{i}].text", t, spans)
                            anon["response"]["output"]["generic"][i]["text"] = mask_with_spans(t, spans)

        # contexts (processa qualquer string)
        def _mask_ctx(path_prefix: str, d):
            if not isinstance(d, dict):
                return
            for k, v in list(d.items()):
                if isinstance(v, str) and v.strip():
                    spans = detect_pii_spans(v)
                    if spans:
                        _priv_write(fh_priv, f"{path_prefix}.{k}", v, spans)
                        d[k] = mask_with_spans(v, spans)

        req_ctx = ((anon.get("request") or {}).get("context") or {})
        _mask_ctx("request.context", req_ctx)

        res_ctx = ((anon.get("response") or {}).get("context") or {})
        _mask_ctx("response.context", res_ctx)

        req_hist = ((anon.get("request") or {}).get("context") or {}).get("history", {})
        if isinstance(req_hist, dict):
            _mask_ctx("request.context.history", req_hist)

        res_hist = ((anon.get("response") or {}).get("context") or {}).get("history", {})
        if isinstance(res_hist, dict):
            _mask_ctx("response.context.history", res_hist)

        logs_anon.append(anon)

    if fh_priv:
        fh_priv.close()
        logging.info(f"Achados de PII salvos em ./{PRIV_FILE}")

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"logs": logs_anon, "pagination": {}}, f, ensure_ascii=False, indent=2)
    logging.info(f"Anonimizado salvo em ./{OUT_FILE}")

if __name__ == "__main__":
    main()
