#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import getpass
from datetime import datetime, timezone
from pathlib import Path


def instalar_dependencia():
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"], stdout=subprocess.DEVNULL)


try:
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509 import NameOID
except ImportError:
    print("Instalando dependência 'cryptography'...")
    instalar_dependencia()
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509 import NameOID


def ler_certificado(caminho, senha):
    try:
        with open(caminho, "rb") as f:
            dados = f.read()
        if isinstance(senha, str):
            senha = senha.encode("utf-8")
        _, cert, _ = pkcs12.load_key_and_certificates(dados, senha)
        return cert
    except Exception:
        return None


def status_validade(dias):
    if dias < 0:
        return f"VENCIDO há {abs(dias)} dia(s)", "❌"
    elif dias == 0:
        return "Vence HOJE!", "🚨"
    elif dias <= 30:
        return f"{dias} dia(s) restantes — ATENÇÃO", "⚠️ "
    elif dias <= 90:
        return f"{dias} dia(s) restantes — PRÓXIMO", "🟡"
    else:
        return f"{dias} dia(s) restantes — OK", "✅"


def linha(char="─", largura=68):
    print(char * largura)


def verificar_certificados(pasta):
    pasta = Path(pasta)
    arquivos = sorted(pasta.glob("*.pfx")) + sorted(pasta.glob("*.p12"))

    if not arquivos:
        print(f"\nNenhum certificado (.pfx ou .p12) encontrado em:\n  {pasta.resolve()}\n")
        print("Coloque os arquivos de certificado nessa pasta e rode novamente.")
        return

    agora = datetime.now(timezone.utc)

    linha("═")
    print("  VERIFICADOR DE CERTIFICADOS DIGITAIS A1")
    print(f"  Data/hora atual : {agora.astimezone().strftime('%d/%m/%Y %H:%M')}")
    print(f"  Pasta           : {pasta.resolve()}")
    print(f"  Certificados    : {len(arquivos)} encontrado(s)")
    linha("═")

    resultados = []

    for arquivo in arquivos:
        print(f"\n📄 {arquivo.name}")
        linha()

        # Tenta sem senha primeiro
        cert = ler_certificado(arquivo, b"")

        if cert is None:
            try:
                senha = getpass.getpass(f"   Senha (deixe em branco se não houver): ")
            except Exception:
                senha = input("   Senha: ")
            cert = ler_certificado(arquivo, senha)

        if cert is None:
            print("   ❌  Não foi possível ler o certificado. Verifique a senha.")
            resultados.append({"arquivo": arquivo.name, "ok": False})
            continue

        inicio = cert.not_valid_before_utc
        fim = cert.not_valid_after_utc
        dias_restantes = (fim - agora).days

        try:
            nome = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            nome = "Não identificado"

        try:
            org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            org = None

        descricao, icone = status_validade(dias_restantes)

        print(f"   Titular    : {nome}")
        if org:
            print(f"   Organização: {org}")
        print(f"   Válido de  : {inicio.astimezone().strftime('%d/%m/%Y')}")
        print(f"   Válido até : {fim.astimezone().strftime('%d/%m/%Y')}")
        print(f"   Status     : {icone} {descricao}")

        resultados.append({
            "arquivo": arquivo.name,
            "ok": True,
            "nome": nome,
            "inicio": inicio,
            "fim": fim,
            "dias": dias_restantes,
        })

    # Resumo final
    print()
    linha("═")
    print("  RESUMO")
    linha("═")

    validos = [r for r in resultados if r.get("ok") and r.get("dias", -1) >= 0]
    vencidos = [r for r in resultados if r.get("ok") and r.get("dias", 0) < 0]
    com_erro = [r for r in resultados if not r.get("ok")]

    if validos:
        print(f"  ✅ Válidos  : {len(validos)}")
    if vencidos:
        print(f"  ❌ Vencidos : {len(vencidos)}")
    if com_erro:
        print(f"  ⚠️  Com erro : {len(com_erro)}")

    # Destaque para os que vencem em breve
    proximos = [r for r in validos if r["dias"] <= 90]
    if proximos:
        print()
        print("  Certificados vencendo nos próximos 90 dias:")
        for r in sorted(proximos, key=lambda x: x["dias"]):
            print(f"    • {r['arquivo']} — {r['dias']} dia(s) ({r['fim'].astimezone().strftime('%d/%m/%Y')})")

    linha("═")


if __name__ == "__main__":
    pasta = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
    verificar_certificados(pasta)
    print()
    input("Pressione Enter para sair...")
