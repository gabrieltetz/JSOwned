#!/usr/bin/env python3
import argparse
import concurrent.futures as cf
import hashlib
import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse

import requests


# -----------------------------
# Utils: leitura e normalização
# -----------------------------
def read_lines(path: str) -> List[str]:
    with open(path, "rb") as f:
        raw = f.read()

    for enc in ("utf-8", "latin-1"):
        try:
            txt = raw.decode(enc)
            break
        except UnicodeDecodeError:
            txt = None

    if txt is None:
        txt = raw.decode("utf-8", errors="ignore")

    lines = []
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def normalize_url(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", u):
        u = "http://" + u
    return u


def sha1_short(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:10]


def snippet(text: str, start: int, end: int, radius: int = 80) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    s = text[a:b]
    return s.replace("\n", "\\n").replace("\r", "\\r")


# -----------------------------
# Regex compile robusto
# -----------------------------
def safe_compile(pattern: str) -> Optional[re.Pattern]:
    """
    Compila regex com fallback pra padrões que colocam (?i) no meio.
    """
    try:
        return re.compile(pattern, re.MULTILINE | re.DOTALL)
    except re.error:
        try:
            cleaned = pattern.replace("(?i)", "")
            return re.compile(cleaned, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        except re.error:
            return None


# -----------------------------
# Severidade / tipo (heurística)
# -----------------------------
def classify_by_regex(raw_regex: str, match_text: str) -> Tuple[str, str]:
    """
    Retorna (severity, kind) baseado em padrões comuns.
    Ajuste livre conforme seu gosto.
    """
    r = raw_regex.lower()
    m = match_text.lower()

    # Private keys / service account
    if "begin rsa private key" in r or "begin private key" in r or "begin openssh private key" in r:
        return ("CRITICAL", "PrivateKey")
    if '"type": "service_account"' in raw_regex or "service_account" in r:
        return ("CRITICAL", "GCPServiceAccount")

    # AWS keys
    if "akia" in r or "asia" in r or "a3t" in r or "ltai" in r:
        return ("HIGH", "CloudKey")

    # GitHub / GitLab / Slack / Stripe / etc (heurísticas)
    if "ghp_" in r or "gho_" in r or "ghu" in r or "ghs" in r or "ghr_" in r:
        return ("HIGH", "GitHubToken")
    if "glpat-" in r:
        return ("HIGH", "GitLabToken")
    if "xox" in r:
        return ("HIGH", "SlackToken")
    if "shpat_" in r or "shpca_" in r or "shppa_" in r or "shpss_" in r:
        return ("HIGH", "ShopifyToken")
    if "mailgun" in r or "mailchimp" in r:
        return ("MEDIUM", "EmailProviderKey")
    if "newrelic" in r or "nrak" in r or "nrjs" in r:
        return ("MEDIUM", "APMKey")

    # Genérico: key/token/secret/password
    if "password" in r or "secret" in r or "token" in r or "api" in r or "key" in r:
        # palavra pura "password" ou "secret" dá muito falso positivo
        if raw_regex.strip() in ("password", "secret"):
            return ("LOW", "Keyword")
        return ("MEDIUM", "GenericCredentialLike")

    # Default
    return ("INFO", "Unknown")


# -----------------------------
# JWT + Base64 detectors + decode
# -----------------------------
JWT_RE = re.compile(r"\beyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\b")
# base64 razoável (evita lixo): tamanho >= 24, múltiplo de 4 opcional com =
B64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b")

def _b64_urlsafe_pad(s: str) -> str:
    # JWT usa base64url sem padding
    pad = (-len(s)) % 4
    return s + ("=" * pad)

def try_decode_jwt(token: str) -> Optional[Dict]:
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = base64.urlsafe_b64decode(_b64_urlsafe_pad(parts[0])).decode("utf-8", errors="replace")
        payload = base64.urlsafe_b64decode(_b64_urlsafe_pad(parts[1])).decode("utf-8", errors="replace")
        # signature é binário — não precisa decodificar
        return {"header": header, "payload": payload}
    except Exception:
        return None

def try_decode_base64(s: str) -> Optional[str]:
    import base64
    # Evita decodar coisas muito pequenas ou muito grandes
    if len(s) < 24 or len(s) > 5000:
        return None
    # Filtra strings que parecem ser “hex” ou “uuid” e não base64
    if re.fullmatch(r"[0-9a-fA-F]{24,}", s):
        return None
    try:
        raw = base64.b64decode(s, validate=False)
        # Se virar muito binário, aborta
        if not raw:
            return None
        # Heurística: se tiver muitos bytes não imprimíveis, não mostra
        printable = sum(1 for b in raw[:200] if 32 <= b <= 126 or b in (9, 10, 13))
        if printable / max(1, min(len(raw), 200)) < 0.65:
            return None
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


# -----------------------------
# HTML parsing: inline scripts + src
# -----------------------------
SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*)>(.*?)</script\s*>",
    flags=re.IGNORECASE | re.DOTALL
)
SCRIPT_SRC_RE = re.compile(
    r'\bsrc\s*=\s*["\']([^"\']+)["\']',
    flags=re.IGNORECASE
)


def extract_scripts_from_html(html: str, base_url: str) -> Tuple[List[str], List[str]]:
    """
    Retorna (inline_scripts, linked_js_urls)
    """
    inline = []
    linked = []

    for attrs, body in SCRIPT_TAG_RE.findall(html):
        src_m = SCRIPT_SRC_RE.search(attrs or "")
        if src_m:
            src = src_m.group(1).strip()
            # ignora data: e coisas estranhas
            if src.lower().startswith("data:"):
                continue
            linked.append(urljoin(base_url, src))
        else:
            # inline
            if body and body.strip():
                inline.append(body)

    # Dedup
    inline = list(dict.fromkeys(inline))
    linked = list(dict.fromkeys(linked))
    return inline, linked


# -----------------------------
# Networking
# -----------------------------
def fetch_url_text(
    session: requests.Session,
    url: str,
    timeout: int,
    max_kb: int,
) -> Tuple[Optional[int], str, Optional[str]]:
    """
    Retorna (status, content_type, text)
    """
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
    except requests.RequestException:
        return None, "", None

    status = r.status_code
    ctype = r.headers.get("Content-Type", "") or ""

    data = b""
    limit = max_kb * 1024
    try:
        for chunk in r.iter_content(chunk_size=8192):
            if not chunk:
                continue
            data += chunk
            if len(data) >= limit:
                break
    except requests.RequestException:
        return status, ctype, None

    enc = r.encoding or "utf-8"
    try:
        text = data.decode(enc, errors="replace")
    except LookupError:
        text = data.decode("utf-8", errors="replace")

    return status, ctype, text


def looks_like_html(content_type: str, text: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    # fallback heurístico
    if text and "<html" in text.lower():
        return True
    if text and "<script" in text.lower():
        return True
    return False


# -----------------------------
# Finding model
# -----------------------------
@dataclass
class Finding:
    target: str
    source: str            # "regex" | "jwt" | "base64" | "inline"
    severity: str
    kind: str
    regex_id: Optional[str]
    regex: Optional[str]
    match: str
    pos: Optional[str]
    context: Optional[str]
    decoded: Optional[Dict]


def dedupe_key(f: Finding) -> str:
    # Dedup por tipo + match + target (evita repetição infinita)
    base = f"{f.target}|{f.kind}|{f.match}"
    return sha1_short(base)


# -----------------------------
# Scanning logic
# -----------------------------
def scan_text_with_regexes(
    text: str,
    target: str,
    patterns: List[Tuple[str, re.Pattern]],
) -> List[Finding]:
    findings: List[Finding] = []

    for raw, creg in patterns:
        for m in creg.finditer(text):
            match_txt = m.group(0)
            sev, kind = classify_by_regex(raw, match_txt)
            rid = sha1_short(raw)
            findings.append(
                Finding(
                    target=target,
                    source="regex",
                    severity=sev,
                    kind=kind,
                    regex_id=rid,
                    regex=raw,
                    match=match_txt,
                    pos=f"{m.start()}-{m.end()}",
                    context=snippet(text, m.start(), m.end()),
                    decoded=None,
                )
            )

    return findings


def scan_text_for_jwt_base64(text: str, target: str) -> List[Finding]:
    findings: List[Finding] = []

    # JWT
    for m in JWT_RE.finditer(text):
        tok = m.group(0)
        decoded = try_decode_jwt(tok)
        if decoded:
            findings.append(
                Finding(
                    target=target,
                    source="jwt",
                    severity="MEDIUM",   # você pode elevar pra HIGH se quiser
                    kind="JWT",
                    regex_id=None,
                    regex=None,
                    match=tok,
                    pos=f"{m.start()}-{m.end()}",
                    context=snippet(text, m.start(), m.end()),
                    decoded=decoded,
                )
            )

    # Base64 strings
    # (muitos falsos positivos, então mantive LOW/MEDIUM e só quando decodifica texto legível)
    for m in B64_RE.finditer(text):
        b64s = m.group(0)
        decoded_txt = try_decode_base64(b64s)
        if decoded_txt:
            findings.append(
                Finding(
                    target=target,
                    source="base64",
                    severity="LOW",
                    kind="Base64DecodedText",
                    regex_id=None,
                    regex=None,
                    match=b64s,
                    pos=f"{m.start()}-{m.end()}",
                    context=snippet(text, m.start(), m.end()),
                    decoded={"decoded": decoded_txt[:2000]},
                )
            )

    return findings


def scan_one_url(
    url: str,
    patterns: List[Tuple[str, re.Pattern]],
    timeout: int,
    max_kb: int,
    verify_tls: bool,
    mode: str,
    also_linked_js: bool,
    max_linked_js: int,
) -> List[Finding]:
    findings: List[Finding] = []

    headers = {
        "User-Agent": "JSOwned-Scanner/2.1",
        "Accept": "*/*",
    }

    with requests.Session() as session:
        session.headers.update(headers)
        session.verify = verify_tls

        status, ctype, text = fetch_url_text(session, url, timeout, max_kb)
        if not text:
            return findings

        # Decide o modo
        is_html = looks_like_html(ctype, text)
        eff_mode = mode
        if mode == "auto":
            eff_mode = "html" if is_html else "js"

        if eff_mode == "js":
            # Scaneia o texto todo como JS
            findings.extend(scan_text_with_regexes(text, url, patterns))
            findings.extend(scan_text_for_jwt_base64(text, url))
            return findings

        # eff_mode == "html"
        # 1) scan no HTML em si (às vezes o secret tá no HTML)
        findings.extend(scan_text_with_regexes(text, url, patterns))
        findings.extend(scan_text_for_jwt_base64(text, url))

        # 2) inline scripts
        inline_scripts, linked = extract_scripts_from_html(text, url)

        for idx, script_body in enumerate(inline_scripts[:100]):  # limite pra não explodir
            virtual_target = f"{url}#inline_script_{idx+1}"
            # marca source como inline (mas ainda usa as mesmas regex)
            inline_findings = scan_text_with_regexes(script_body, virtual_target, patterns)
            for f in inline_findings:
                f.source = "inline"
            findings.extend(inline_findings)

            inline_jwtb64 = scan_text_for_jwt_base64(script_body, virtual_target)
            for f in inline_jwtb64:
                f.source = "inline"
            findings.extend(inline_jwtb64)

        # 3) scripts externos (opcional)
        if also_linked_js and linked:
            for jsu in linked[:max_linked_js]:
                st2, ct2, js_text = fetch_url_text(session, jsu, timeout, max_kb)
                if not js_text:
                    continue
                findings.extend(scan_text_with_regexes(js_text, jsu, patterns))
                findings.extend(scan_text_for_jwt_base64(js_text, jsu))

        return findings


# -----------------------------
# Output
# -----------------------------
def format_finding_txt(f: Finding) -> str:
    head = [
        f"TARGET: {f.target}",
        f"SEVERITY: {f.severity}",
        f"KIND: {f.kind}",
        f"SOURCE: {f.source}",
    ]
    if f.regex_id and f.regex:
        head.append(f"REGEX[{f.regex_id}]: {f.regex}")

    body = [
        f"MATCH: {f.match}",
    ]
    if f.pos:
        body.append(f"POS: {f.pos}")
    if f.context:
        body.append(f"CTX: {f.context}")

    if f.decoded:
        # imprime em JSON para não quebrar formatação
        body.append("DECODED: " + json.dumps(f.decoded, ensure_ascii=False))

    return "\n".join(head + body) + "\n" + ("-" * 60) + "\n"


def main():
    ap = argparse.ArgumentParser(description="JSOwned secrets scanner (inline JS + JWT/Base64 + severidade)")

    ap.add_argument("input_path", help="arquivo com URLs (JS ou páginas HTML), 1 por linha")
    ap.add_argument("regex_path", help="arquivo com regexes (1 por linha)")

    ap.add_argument("-o", "--output", dest="output_path", default="findings.txt",
                    help="arquivo de saída (default: findings.txt)")
    ap.add_argument("--append", action="store_true",
                    help="append no arquivo de saída (não reseta)")
    ap.add_argument("-t", "--threads", type=int, default=15,
                    help="threads (default: 15)")
    ap.add_argument("--timeout", type=int, default=10,
                    help="timeout por request (s)")
    ap.add_argument("--max-kb", type=int, default=1024,
                    help="limite de leitura por resposta (KB)")
    ap.add_argument("--insecure", action="store_true",
                    help="desabilitar validação TLS")

    ap.add_argument("--mode", choices=["js", "html", "auto"], default="js",
                    help="js=scan direto; html=extrai <script>; auto=detecta por content-type/heurística")
    ap.add_argument("--also-linked-js", action="store_true",
                    help="no modo html, também baixa e escaneia scripts com src=...")
    ap.add_argument("--max-linked-js", type=int, default=30,
                    help="limite de scripts externos por página (default: 30)")

    ap.add_argument("--json", dest="json_output", default="",
                    help="opcional: salvar também em JSON (arquivo)")

    args = ap.parse_args()

    urls_raw = read_lines(args.input_path)
    urls = [normalize_url(u) for u in urls_raw]
    urls = [u for u in urls if u]

    regex_lines = read_lines(args.regex_path)
    patterns: List[Tuple[str, re.Pattern]] = []
    bad = 0
    for r in regex_lines:
        creg = safe_compile(r)
        if not creg:
            bad += 1
            continue
        patterns.append((r, creg))

    if not urls or not patterns:
        print("[-] Nada para processar (urls ou regex vazios).")
        sys.exit(1)

    if bad:
        print(f"[!] {bad} regex(es) inválida(s) foram ignoradas.")

    mode = "a" if args.append else "w"
    out = open(args.output_path, mode, encoding="utf-8", errors="ignore")

    if not args.append:
        out.write("# JSOwned secrets scan\n")
        out.write(f"# INPUT: {args.input_path}\n")
        out.write(f"# REGEX: {args.regex_path}\n")
        out.write(f"# MODE: {args.mode}  linked_js={args.also_linked_js}\n")
        out.write("# --------------------------------------------\n")
        out.flush()

    verify_tls = not args.insecure

    total = 0
    dedupe: Set[str] = set()
    json_findings: List[Dict] = []

    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(
                scan_one_url,
                u,
                patterns,
                args.timeout,
                args.max_kb,
                verify_tls,
                args.mode,
                args.also_linked_js,
                args.max_linked_js,
            ): u
            for u in urls
        }

        for fut in cf.as_completed(futures):
            try:
                findings = fut.result()
            except Exception:
                continue

            for f in findings:
                k = dedupe_key(f)
                if k in dedupe:
                    continue
                dedupe.add(k)

                out.write(format_finding_txt(f))
                total += 1

                if args.json_output:
                    json_findings.append(asdict(f))

            out.flush()

    out.close()

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as jf:
            json.dump(json_findings, jf, ensure_ascii=False, indent=2)

    print(f"[+] Scan finalizado: {len(urls)} URL(s), {total} achado(s) únicos.")
    if args.json_output:
        print(f"[+] JSON salvo em: {args.json_output}")


if __name__ == "__main__":
    main()
