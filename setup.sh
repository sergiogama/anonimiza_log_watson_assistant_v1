#!/bin/zsh
/usr/local/opt/python@3.12/bin/python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# python -m spacy download pt_core_news_md
# python -m spacy download en_core_web_md  

