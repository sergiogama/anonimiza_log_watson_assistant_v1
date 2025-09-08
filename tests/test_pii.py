# tests/test_pii_addresses_docs.py
#
# Testes focados em ENDEREÇOS (muitas variações) e DOCUMENTOS via REGEX
# Troque 'your_module_filename' pelo nome REAL do seu script (sem .py).
#
# Rodar:  pytest -q
#
import re
import pytest

from anon_logs_wa import detect_pii_spans, mask_with_spans, cpf_is_valid

# ----------------- Helpers -----------------

def _masked(text: str) -> str:
    return mask_with_spans(text, detect_pii_spans(text))

def _has(label: str, masked_text: str) -> bool:
    return f"[{label}]" in masked_text

def _not_contains(any_of: list[str], masked_text: str) -> bool:
    return not any(tok in masked_text for tok in any_of)

# ----------------- ENDEREÇOS: palavras-chave + número expandido -----------------
# Observação: a lógica de endereço no script depende de palavras-chave
# (rua, av, avenida, alameda, travessa/tv., estrada, rodovia/rod., praça/praca,
# largo/lgo., quadra/qd., lote/lt.) + expansão do número ao final.

@pytest.mark.parametrize("s", [
    "moro na Rua das Flores, 123",
    "meu endereço: rua das Flores, 123",
    "moro na R. das Acácias 45",
    "moro na Av Paulista, 1000",
    "moro na Av. Paulista 1578",
    "endereço: Avenida Rio Branco, 890",
    "alameda dos Anjos, 77",
    "travessa do Sol, 12",
    "Tv. das Palmeiras, 55",
    "estrada do Coco, 200A",
    "rodovia BR-116, 100/12",
    "rod. Raposo Tavares, 321",
    "praça da Sé, 10",
    "praca da Sé, 10",
    "largo do Machado, 30",
    "lgo. do Machado, 30",
    "quadra 12, 45",
    "qd. 3, 5",
    "lote 7, 22",
    "lt. 7, 22",
])
def test_address_keywords_and_number_expansion(s):
    masked = _masked(s)
    assert _has("ADDRESS", masked)
    # números presentes não devem "vazar" após mascarar
    numeros = re.findall(r"\b\d[\dA-Za-z/]*\b", s)
    assert _not_contains(numeros, masked)

# ----------------- ENDEREÇOS: variações de sufixos de número -----------------

@pytest.mark.parametrize("s", [
    "Rua Azul, 45",
    "Rua Azul nº 45",
    "Rua Azul n° 123",
    "Rua Azul, 200A",
    "Rua Azul, 10/12",
    "Av Verde nº12",
    "Av Verde n°12",
])
def test_address_number_suffix_variants(s):
    masked = _masked(s)
    assert _has("ADDRESS", masked)
    numeros = re.findall(r"\b\d[\dA-Za-z/]*\b", s)
    assert _not_contains(numeros, masked)

# ----------------- ENDEREÇOS: com bairro/complemento/CEP -----------------

@pytest.mark.parametrize("s", [
    "Rua das Laranjeiras, 50, Bairro Centro, CEP 01311-000",
    "Av. Brasil 1200, Jardim Paulista, CEP 01311000",
    "R. Bela Vista, 77, apto 101, CEP 22793-080",
    "Alameda Santos, 1001, Bloco B, CEP 01419-001",
    "Travessa Azul, 22, sala 402, CEP 88010-400",
])
def test_address_with_bairro_complement_and_cep(s):
    masked = _masked(s)
    # Endereço deve ser mascarado
    assert _has("ADDRESS", masked)
    # CEP deve ser mascarado separadamente
    assert _has("CEP", masked)
    # números finais do logradouro não devem sobrar
    nums = re.findall(r"\b\d[\dA-Za-z/]*\b", s.split(",")[0])
    assert _not_contains(nums, masked)

# ----------------- CPF -----------------

def test_cpf_valido():
    assert cpf_is_valid("08286669894") is True

@pytest.mark.parametrize("s", [
    "meu CPF é 082.866.698-94",
    "CPF: 08286669894",
])
def test_mask_cpf_format_positional(s):
    masked = _masked(s)
    assert _has("CPF", masked)
    assert "082.866.698-94" not in masked
    assert "08286669894" not in masked

def test_mask_cpf_contextual_invalido():
    s = "meu CPF é 082.866.6998-94"  # inválido, mas contextual; sua lógica mascara
    masked = _masked(s)
    assert _has("CPF", masked)

def test_mask_cpf_11digitos_contiguos_invalido_mascarado():
    s = "11111111111"  # sua regra mascara qualquer 11 dígitos contíguos
    masked = _masked(s)
    assert _has("CPF", masked)

# ----------------- CNPJ -----------------

@pytest.mark.parametrize("s", [
    "CNPJ: 12.345.678/0001-95",
    "Empresa 12.345.678/0001-95",
])
def test_mask_cnpj(s):
    masked = _masked(s)
    assert _has("CNPJ", masked)

# ----------------- RG -----------------

@pytest.mark.parametrize("s", [
    "RG: 12.345.678-9",
    "RG 1.234.567-8",
])
def test_mask_rg(s):
    masked = _masked(s)
    assert _has("RG", masked)

# ----------------- CEP -----------------

@pytest.mark.parametrize("s", [
    "CEP 01311-000",
    "CEP 01311000",
    "Endereço: Rua A, 1, CEP 22793-080 RJ",
])
def test_mask_cep(s):
    masked = _masked(s)
    assert _has("CEP", masked)

# ----------------- Cartão (Luhn) -----------------

@pytest.mark.parametrize("s", [
    "Cartão 4111 1111 1111 1111",   # VISA teste (Luhn válido)
    "Cartão: 5500-0000-0000-0004",  # Master (exemplo válido)
])
def test_mask_card_valid(s):
    masked = _masked(s)
    assert _has("CARD", masked)

def test_card_invalido_nao_mascarar():
    s = "Cartão 1234 5678 9012 3456"  # Luhn inválido
    masked = _masked(s)
    assert not _has("CARD", masked)

# ----------------- Telefone (BR) -----------------
# Requer biblioteca phonenumbers instalada (já é dependência do script).

@pytest.mark.parametrize("s", [
    "tel: +55 (11) 91234-5678",
    "telefone (21) 2345-6789",
    "contato 5511912345678",
    "fone +55 21 2345 6789",
])
def test_mask_phone_br(s):
    masked = _masked(s)
    assert _has("PHONE", masked)

# ----------------- Casos mistos -----------------

@pytest.mark.parametrize("s", [
    "Meu e-mail é a@b.com e moro na Rua Verde, 50. CPF 082.866.698-94.",
    "Endereço Av. Paulista, 1578, CEP 01311-000; RG 12.345.678-9.",
    "CNPJ 12.345.678/0001-95; telefone +55 (11) 91234-5678; Rua Azul, 45.",
])
def test_mistos(s):
    masked = _masked(s)
    # Deve mascarar pelo menos um de cada quando presente
    if "@" in s:
        assert _has("EMAIL", masked)
    if "CPF" in s or re.search(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}", s):
        assert _has("CPF", masked)
    if "CNPJ" in s or re.search(r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}", s):
        assert _has("CNPJ", masked)
    if "RG" in s or re.search(r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b", s):
        assert _has("RG", masked)
    if "CEP" in s or re.search(r"\b\d{5}-?\d{3}\b", s):
        assert _has("CEP", masked)
    if any(k in s.lower() for k in ["rua","r.","av","avenida","alameda","travessa","tv.","estrada","rodovia","rod.","praça","praca","largo","lgo.","quadra","qd.","lote","lt."]):
        assert _has("ADDRESS", masked)
