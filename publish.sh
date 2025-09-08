#!/bin/zsh
# Script para publicar atualizações no GitHub

git status
git add .
git status
echo "Digite uma mensagem de commit:"
read commit_msg
git commit -m "$commit_msg"
git push
