@echo off
chcp 65001 >nul
python "%~dp0verificar_certificados.py" "%~dp0"
