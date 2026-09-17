#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analisador de Emails para Deteccao de Phishing
================================================

Analisa arquivos de email (.eml ou .msg) e extrai informacoes relevantes
para uma analise de seguranca: cabecalhos, remetente real, autenticacao
(SPF/DKIM/DMARC), links, anexos, indicadores de risco, e gera um score
de suspeita com um relatorio detalhado (texto e JSON).

USO:
    python phishing_analyzer.py caminho\\para\\email.eml
    python phishing_analyzer.py caminho\\para\\email.msg
    python phishing_analyzer.py caminho\\para\\email.eml --json relatorio.json

Dependencias opcionais:
    - Para arquivos .msg (Outlook): pip install extract-msg
      (sem essa lib, converta o .msg para .eml antes, ou salve o email
      como "Salvar como > Texto do Outlook" / .eml)

Este script NAO faz requisicoes de rede (sem consultas DNS/WHOIS/blacklist
externas) para ser seguro de rodar sobre emails potencialmente maliciosos.
Ele analisa apenas o conteudo estatico do email.
"""

import argparse
import email
import hashlib
import ipaddress
import json
import os
import re
import sys
from email import policy
from email.utils import parseaddr, getaddresses, parsedate_to_datetime
from urllib.parse import urlparse

# ----------------------------------------------------------------------------
# Listas de referencia para heuristicas
# ----------------------------------------------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "lnkd.in",
    "tiny.cc", "shorte.st", "adf.ly", "clck.ru", "v.gd", "qrco.de",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "work", "support",
    "gq", "tk", "ml", "cf", "ga", "buzz", "loan", "win", "download",
    "review", "country", "kim", "science", "party", "date", "faith",
    "icu", "cn", "ru", "su",
}

URGENCY_KEYWORDS = [
    "urgente", "urgent", "immediate action", "acao imediata", "acao urgente",
    "sua conta sera bloqueada", "conta suspensa", "account suspended",
    "verifique sua conta", "verify your account", "confirme seus dados",
    "confirm your identity", "clique aqui", "click here", "click below",
    "senha expirou", "password expires", "password will expire",
    "atualize seus dados", "update your information", "pagamento pendente",
    "payment overdue", "fatura em anexo", "invoice attached",
    "premio", "you have won", "voce ganhou", "restricted account",
    "unusual activity", "atividade suspeita", "security alert",
    "alerta de seguranca", "last warning", "ultimo aviso",
    "within 24 hours", "em 24 horas", "suspend your account",
    "limited time", "tempo limitado", "aja agora", "act now",
]

BRAND_IMPERSONATION_HINTS = [
    "microsoft", "office365", "outlook", "google", "gmail", "apple",
    "icloud", "paypal", "amazon", "netflix", "dhl", "correios",
    "banco", "bank", "santander", "bradesco", "itau", "caixa",
    "nubank", "meo", "nos", "vodafone", "dropbox", "docusign",
    "adobe", "linkedin", "facebook", "instagram", "whatsapp",
]

DANGEROUS_ATTACHMENT_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".hta",
    ".lnk", ".iso", ".img", ".dll", ".reg", ".chm", ".docm", ".xlsm",
    ".pptm", ".one",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "gmx.com", "mail.com",
    "zoho.com", "yandex.com",
}


# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------

def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_of_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def extract_domain(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().strip(">")


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def get_tld(host: str) -> str:
    parts = host.rstrip(".").split(".")
    return parts[-1].lower() if parts else ""


def levenshtein_close(a: str, b: str, max_dist: int = 2) -> bool:
    """Retorna True se 'a' e 'b' sao parecidos (possivel typosquatting)."""
    if a == b:
        return False
    if abs(len(a) - len(b)) > max_dist:
        return False
    # Distancia de edicao simples (Levenshtein)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    dist = prev[-1]
    return 0 < dist <= max_dist


# ----------------------------------------------------------------------------
# Parsing de .msg (Outlook) - opcional via extract-msg
# ----------------------------------------------------------------------------

def load_message(path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".msg":
        try:
            import extract_msg  # type: ignore
        except ImportError:
            print(
                "[ERRO] Para analisar arquivos .msg instale a dependencia:\n"
                "    pip install extract-msg\n"
                "Alternativa: no Outlook, abra o email e use 'Arquivo > Salvar como' "
                "escolhendo o formato .eml (ou 'Texto do Outlook (*.txt)' e depois "
                "reencaminhe como .eml), ou arraste o email para uma pasta para "
                "exportar como .msg e converta com uma ferramenta online confiavel.",
                file=sys.stderr,
            )
            sys.exit(1)
        msg = extract_msg.Message(path)
        # Reconstroi um email.message.EmailMessage a partir dos campos do .msg
        eml = email.message.EmailMessage(policy=policy.default)
        eml["From"] = msg.sender or ""
        eml["To"] = msg.to or ""
        eml["Cc"] = msg.cc or ""
        eml["Subject"] = msg.subject or ""
        eml["Date"] = msg.date or ""
        headers_raw = msg.header if hasattr(msg, "header") else None
        if headers_raw:
            # Preserva cabecalhos originais adicionais quando disponiveis
            try:
                original = email.message_from_string(str(headers_raw), policy=policy.default)
                for k, v in original.items():
                    if k.lower() not in ("from", "to", "cc", "subject", "date"):
                        eml[k] = v
            except Exception:
                pass
        body = msg.body or ""
        html_body = getattr(msg, "htmlBody", None)
        if html_body:
            try:
                eml.set_content(body or "")
                eml.add_alternative(
                    html_body.decode("utf-8", errors="ignore")
                    if isinstance(html_body, bytes) else html_body,
                    subtype="html",
                )
            except Exception:
                eml.set_content(body or "")
        else:
            eml.set_content(body or "")
        for att in msg.attachments:
            try:
                eml.add_attachment(
                    att.data,
                    maintype="application",
                    subtype="octet-stream",
                    filename=att.longFilename or att.shortFilename or "anexo",
                )
            except Exception:
                pass
        msg.close()
        return eml
    else:
        with open(path, "rb") as f:
            raw = f.read()
        return email.message_from_bytes(raw, policy=policy.default)


# ----------------------------------------------------------------------------
# Extracao de cabecalhos e cadeia de "Received"
# ----------------------------------------------------------------------------

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)


def parse_received_chain(msg) -> list:
    chain = []
    for received in msg.get_all("Received", []):
        ips = IP_RE.findall(received)
        from_match = re.search(r"from\s+([^\s]+)", received)
        by_match = re.search(r"by\s+([^\s]+)", received)
        chain.append({
            "raw": received.replace("\n", " ").replace("\t", " ").strip(),
            "ips_found": list(dict.fromkeys(ips)),
            "from": from_match.group(1) if from_match else None,
            "by": by_match.group(1) if by_match else None,
        })
    return chain


def parse_auth_results(msg) -> dict:
    """Extrai resultados de SPF / DKIM / DMARC do cabecalho Authentication-Results."""
    result = {"spf": None, "dkim": None, "dmarc": None, "raw": []}
    for header_name in ("Authentication-Results", "ARC-Authentication-Results"):
        for val in msg.get_all(header_name, []):
            result["raw"].append(val.replace("\n", " ").strip())
            for mech, key in (("spf", "spf"), ("dkim", "dkim"), ("dmarc", "dmarc")):
                m = re.search(rf"{mech}=(\w+)", val, re.IGNORECASE)
                if m and result[key] is None:
                    result[key] = m.group(1).lower()
    # Received-SPF alternativo
    spf_header = msg.get("Received-SPF")
    if spf_header and result["spf"] is None:
        m = re.search(r"^(\w+)", spf_header.strip())
        if m:
            result["spf"] = m.group(1).lower()
    return result


# ----------------------------------------------------------------------------
# Extracao de corpo, links e anexos
# ----------------------------------------------------------------------------

HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
LINK_TEXT_RE = re.compile(r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                           re.IGNORECASE | re.DOTALL)
PLAIN_URL_RE = re.compile(r'(https?://[^\s<>"\')]+)', re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


def get_bodies(msg):
    text_body = ""
    html_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if ctype == "text/plain" and isinstance(content, str):
                text_body += content
            elif ctype == "text/html" and isinstance(content, str):
                html_body += content
    else:
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if msg.get_content_type() == "text/html":
            html_body = content if isinstance(content, str) else ""
        else:
            text_body = content if isinstance(content, str) else ""
    return text_body, html_body


def extract_links(text_body: str, html_body: str) -> list:
    links = []
    seen = set()

    for href, inner_html in LINK_TEXT_RE.findall(html_body):
        display_text = TAG_RE.sub("", inner_html).strip()
        key = (href, display_text)
        if key in seen:
            continue
        seen.add(key)
        links.append({"url": href, "display_text": display_text})

    # hrefs sem par de texto capturado acima (tags auto-fechadas, etc.)
    for href in HREF_RE.findall(html_body):
        if not any(l["url"] == href for l in links):
            links.append({"url": href, "display_text": ""})

    for url in PLAIN_URL_RE.findall(text_body):
        if not any(l["url"] == url for l in links):
            links.append({"url": url, "display_text": ""})

    return links


def analyze_link(link: dict, sender_domain: str) -> dict:
    url = link["url"]
    display_text = link.get("display_text", "")
    flags = []
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
    except Exception:
        host = ""

    if url.lower().startswith("mailto:"):
        return {**link, "host": None, "flags": []}

    if not host:
        flags.append("URL sem host identificavel / malformada")

    if is_ip(host):
        flags.append("Link aponta diretamente para um endereco IP (comum em phishing)")

    if host in URL_SHORTENERS:
        flags.append(f"Uso de encurtador de URL ({host}) - destino real oculto")

    tld = get_tld(host) if host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Dominio com TLD frequentemente associado a abuso (.{tld})")

    if host.count("-") >= 3:
        flags.append("Dominio com muitos hifens (padrao comum em dominios fraudulentos)")

    if host.count(".") >= 4:
        flags.append("Dominio com muitos subdominios (pode tentar ofuscar o dominio real)")

    # Texto do link (ex: "www.paypal.com") nao bate com o destino real
    text_url_match = re.search(r"([a-z0-9.-]+\.[a-z]{2,})", display_text.lower())
    if text_url_match and host:
        claimed_domain = text_url_match.group(1)
        if claimed_domain != host and claimed_domain not in host:
            flags.append(
                f"Texto do link exibe um dominio diferente do destino real "
                f"('{claimed_domain}' != '{host}')"
            )

    # Possivel impersonation / typosquatting de marca conhecida
    if host and sender_domain:
        base_sender = sender_domain.split(".")[0]
        base_host = host.split(".")[0]
        if base_sender and base_host and levenshtein_close(base_sender, base_host):
            flags.append(
                f"Dominio do link ('{host}') e visualmente parecido com o dominio "
                f"do remetente ('{sender_domain}') - possivel typosquatting"
            )

    for brand in BRAND_IMPERSONATION_HINTS:
        if brand in display_text.lower() and host and brand not in host:
            flags.append(
                f"Texto do link menciona '{brand}' mas o dominio real e '{host}' "
                f"- possivel falsificacao de marca"
            )
            break

    return {**link, "host": host, "flags": flags}


def extract_attachments(msg) -> list:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        if "attachment" not in disp and not filename:
            continue
        if part.get_content_maintype() == "multipart":
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        ext = os.path.splitext(filename or "")[1].lower()
        flags = []
        if ext in DANGEROUS_ATTACHMENT_EXT:
            flags.append(f"Extensao potencialmente perigosa ({ext})")
        if filename and filename.lower().count(".") >= 2:
            fake_ext_match = re.search(r"\.\w+\.\w+$", filename.lower())
            if fake_ext_match:
                flags.append(
                    "Nome de arquivo com dupla extensao (tentativa de disfarce, "
                    f"ex: 'fatura.pdf.exe')"
                )
        attachments.append({
            "filename": filename or "(sem nome)",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": sha256_of_bytes(payload) if payload else None,
            "md5": md5_of_bytes(payload) if payload else None,
            "flags": flags,
        })
    return attachments


# ----------------------------------------------------------------------------
# Analise principal
# ----------------------------------------------------------------------------

def analyze_email(msg) -> dict:
    report = {}

    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")
    to_raw = msg.get("To", "")
    subject = msg.get("Subject", "") or ""
    date_raw = msg.get("Date", "")

    from_name, from_addr = parseaddr(from_raw)
    _, reply_to_addr = parseaddr(reply_to_raw)
    _, return_path_addr = parseaddr(return_path_raw)

    from_domain = extract_domain(from_addr)
    reply_to_domain = extract_domain(reply_to_addr)
    return_path_domain = extract_domain(return_path_addr)

    try:
        parsed_date = parsedate_to_datetime(date_raw) if date_raw else None
    except Exception:
        parsed_date = None

    header_flags = []

    if reply_to_addr and reply_to_domain and reply_to_domain != from_domain:
        header_flags.append(
            f"Reply-To ('{reply_to_addr}') difere do From ('{from_addr}') - "
            "respostas seriam enviadas para outro endereco"
        )

    if return_path_addr and return_path_domain and return_path_domain != from_domain:
        header_flags.append(
            f"Return-Path ('{return_path_addr}') difere do dominio do From "
            f"('{from_domain}') - possivel envelope-from falsificado"
        )

    if from_name:
        for brand in BRAND_IMPERSONATION_HINTS:
            if brand in from_name.lower() and from_domain and brand not in from_domain:
                header_flags.append(
                    f"Nome de exibicao menciona '{brand}' mas o dominio do email "
                    f"e '{from_domain}' - possivel falsificacao de identidade"
                )
                break

    if from_domain in FREEMAIL_DOMAINS:
        header_flags.append(
            f"Remetente usa provedor de email gratuito ({from_domain}) - "
            "incomum para comunicacao corporativa oficial"
        )

    tld = get_tld(from_domain) if from_domain else ""
    if tld in SUSPICIOUS_TLDS:
        header_flags.append(f"Dominio do remetente usa TLD suspeito (.{tld})")

    auth = parse_auth_results(msg)
    if auth["spf"] and auth["spf"] not in ("pass",):
        header_flags.append(f"SPF nao passou (resultado: {auth['spf']})")
    if auth["dkim"] and auth["dkim"] not in ("pass",):
        header_flags.append(f"DKIM nao passou (resultado: {auth['dkim']})")
    if auth["dmarc"] and auth["dmarc"] not in ("pass",):
        header_flags.append(f"DMARC nao passou (resultado: {auth['dmarc']})")
    if not auth["spf"] and not auth["dkim"] and not auth["dmarc"]:
        header_flags.append(
            "Nenhum resultado de autenticacao (SPF/DKIM/DMARC) encontrado nos "
            "cabecalhos - nao foi possivel verificar autenticidade"
        )

    received_chain = parse_received_chain(msg)

    text_body, html_body = get_bodies(msg)
    full_text_for_keywords = (subject + "\n" + text_body + "\n" +
                               TAG_RE.sub(" ", html_body)).lower()

    matched_keywords = sorted({
        kw for kw in URGENCY_KEYWORDS if kw in full_text_for_keywords
    })

    links = extract_links(text_body, html_body)
    analyzed_links = [analyze_link(l, from_domain) for l in links]
    risky_links = [l for l in analyzed_links if l["flags"]]

    attachments = extract_attachments(msg)
    risky_attachments = [a for a in attachments if a["flags"]]

    has_external_images = bool(re.search(r'<img[^>]+src\s*=\s*["\']https?://',
                                          html_body, re.IGNORECASE))

    # ---------------- Score de risco (heuristico, 0-100) ----------------
    score = 0
    score += 12 * len(header_flags)
    score += 15 * len(risky_links)
    score += 20 * len(risky_attachments)
    score += 5 * len(matched_keywords)
    score = min(score, 100)

    if score >= 60:
        veredito = "ALTO RISCO - fortes indicios de phishing/malicious"
    elif score >= 30:
        veredito = "RISCO MODERADO - varios indicadores suspeitos, investigar"
    elif score > 0:
        veredito = "RISCO BAIXO - poucos indicadores, mas revisar mesmo assim"
    else:
        veredito = "SEM INDICADORES OBVIOS - nenhuma heuristica disparou"

    report["identificacao"] = {
        "assunto": subject,
        "de_nome_exibicao": from_name,
        "de_endereco": from_addr,
        "de_dominio": from_domain,
        "reply_to": reply_to_addr or None,
        "return_path": return_path_addr or None,
        "para": to_raw,
        "data": date_raw,
        "data_interpretada": parsed_date.isoformat() if parsed_date else None,
        "message_id": msg.get("Message-ID"),
        "user_agent_x_mailer": msg.get("X-Mailer") or msg.get("User-Agent"),
    }

    report["autenticacao"] = auth
    report["cadeia_received"] = received_chain
    report["indicadores_cabecalho"] = header_flags
    report["palavras_chave_urgencia_ou_engenharia_social"] = matched_keywords
    report["possui_imagens_remotas_html"] = has_external_images
    report["links"] = analyzed_links
    report["links_suspeitos"] = risky_links
    report["anexos"] = attachments
    report["anexos_suspeitos"] = risky_attachments
    report["resumo"] = {
        "score_risco_0_100": score,
        "veredito": veredito,
        "total_indicadores_cabecalho": len(header_flags),
        "total_links": len(analyzed_links),
        "total_links_suspeitos": len(risky_links),
        "total_anexos": len(attachments),
        "total_anexos_suspeitos": len(risky_attachments),
    }

    return report


# ----------------------------------------------------------------------------
# Impressao do relatorio em texto
# ----------------------------------------------------------------------------

def print_report(report: dict) -> None:
    ident = report["identificacao"]
    resumo = report["resumo"]

    line = "=" * 78
    print(line)
    print(" RELATORIO DE ANALISE DE EMAIL - INDICADORES DE PHISHING")
    print(line)

    print(f"\nVeredito: {resumo['veredito']}")
    print(f"Score de risco: {resumo['score_risco_0_100']}/100")

    print("\n--- IDENTIFICACAO ---")
    print(f"Assunto      : {ident['assunto']}")
    print(f"De (nome)    : {ident['de_nome_exibicao']}")
    print(f"De (email)   : {ident['de_endereco']}")
    print(f"De (dominio) : {ident['de_dominio']}")
    print(f"Reply-To     : {ident['reply_to']}")
    print(f"Return-Path  : {ident['return_path']}")
    print(f"Para         : {ident['para']}")
    print(f"Data         : {ident['data']}")
    print(f"Message-ID   : {ident['message_id']}")
    print(f"Mailer/Agent : {ident['user_agent_x_mailer']}")

    print("\n--- AUTENTICACAO (SPF/DKIM/DMARC) ---")
    auth = report["autenticacao"]
    print(f"SPF   : {auth['spf']}")
    print(f"DKIM  : {auth['dkim']}")
    print(f"DMARC : {auth['dmarc']}")

    print(f"\n--- CADEIA DE SERVIDORES (Received) [{len(report['cadeia_received'])}] ---")
    for i, hop in enumerate(report["cadeia_received"], 1):
        ips = ", ".join(hop["ips_found"]) if hop["ips_found"] else "-"
        print(f"  [{i}] from={hop['from']}  by={hop['by']}  ips={ips}")

    print(f"\n--- INDICADORES NOS CABECALHOS [{len(report['indicadores_cabecalho'])}] ---")
    if not report["indicadores_cabecalho"]:
        print("  Nenhum indicador encontrado.")
    for f in report["indicadores_cabecalho"]:
        print(f"  [!] {f}")

    kws = report["palavras_chave_urgencia_ou_engenharia_social"]
    print(f"\n--- PALAVRAS-CHAVE DE ENGENHARIA SOCIAL [{len(kws)}] ---")
    if not kws:
        print("  Nenhuma encontrada.")
    for k in kws:
        print(f"  - {k}")

    print(f"\n--- LINKS ENCONTRADOS [{len(report['links'])}] "
          f"(suspeitos: {len(report['links_suspeitos'])}) ---")
    for l in report["links"]:
        marker = "[!]" if l["flags"] else "   "
        display = f' (texto: "{l["display_text"]}")' if l.get("display_text") else ""
        print(f"  {marker} {l['url']}{display}")
        for flag in l["flags"]:
            print(f"        -> {flag}")

    print(f"\n--- ANEXOS [{len(report['anexos'])}] "
          f"(suspeitos: {len(report['anexos_suspeitos'])}) ---")
    if not report["anexos"]:
        print("  Nenhum anexo.")
    for a in report["anexos"]:
        marker = "[!]" if a["flags"] else "   "
        print(f"  {marker} {a['filename']}  ({a['size_bytes']} bytes)")
        print(f"        SHA256: {a['sha256']}")
        print(f"        MD5   : {a['md5']}")
        for flag in a["flags"]:
            print(f"        -> {flag}")

    if report["possui_imagens_remotas_html"]:
        print("\n[!] O email carrega imagens remotas via HTML - pode ser usado "
              "para rastrear abertura (tracking pixel).")

    print("\n" + line)
    print(" Este relatorio e heuristico e NAO substitui analise humana / "
          "ferramentas especializadas (sandbox, VirusTotal, etc). Use com cautela.")
    print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Analisa um email (.eml ou .msg) em busca de indicadores de phishing."
    )
    parser.add_argument("arquivo", help="Caminho para o arquivo .eml ou .msg")
    parser.add_argument("--json", metavar="SAIDA.json",
                         help="Tambem salva o relatorio completo em JSON neste caminho")
    args = parser.parse_args()

    if not os.path.isfile(args.arquivo):
        print(f"[ERRO] Arquivo nao encontrado: {args.arquivo}", file=sys.stderr)
        sys.exit(1)

    msg = load_message(args.arquivo)
    report = analyze_email(msg)
    print_report(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Relatorio JSON salvo em: {args.json}")


if __name__ == "__main__":
    main()
