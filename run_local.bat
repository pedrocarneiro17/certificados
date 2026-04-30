@echo off
chcp 65001 >nul
title Certificados A1 — Servidor Local

echo.
echo  Instalando dependencias...
pip install -r requirements.txt --quiet

echo  Iniciando servidor...
echo.
echo  Acesse: http://localhost:5000
echo  Pressione Ctrl+C para parar.
echo.

start "" http://localhost:5000
python app.py
