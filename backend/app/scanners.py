import hashlib, ipaddress, mimetypes, re, socket
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from .config import get_settings

def _public_ips(host: str) -> list[str]:
    try:
        values = {item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
        ips = [ipaddress.ip_address(value) for value in values]
    except socket.gaierror as exc:
        raise ValueError("Host could not be resolved") from exc
    if not ips or any(not ip.is_global for ip in ips):
        raise ValueError("Destination resolves to a restricted network")
    return sorted(str(ip) for ip in ips)

def validate_url(value: str):
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Userinfo in URLs is not allowed")
    if parsed.hostname.lower() in {"metadata.google.internal", "instance-data.ec2.internal"}:
        raise ValueError("Metadata endpoint blocked")
    if parsed.port and parsed.port not in {80, 443}:
        raise ValueError("Non-standard ports are not allowed")
    return parsed, _public_ips(parsed.hostname)

def analyze_url(value: str) -> dict:
    parsed, ips = validate_url(value)
    indicators = []
    if parsed.scheme != "https":
        indicators.append({"severity":"medium","title":"Transport is not encrypted","evidence":"URL uses HTTP","recommendation":"Prefer HTTPS."})
    if parsed.hostname.startswith("xn--") or ".xn--" in parsed.hostname:
        indicators.append({"severity":"medium","title":"Punycode hostname","evidence":parsed.hostname,"recommendation":"Verify the domain owner before proceeding."})
    if re.search(r"(?:password|passwd|token|apikey|secret)=", parsed.query, re.I):
        indicators.append({"severity":"high","title":"Sensitive-looking query parameter","evidence":"A credential-like parameter appears in the URL","recommendation":"Do not share credentials in URLs; rotate exposed secrets."})
    return {"url":value,"protocol":parsed.scheme,"domain":parsed.hostname,"port":parsed.port or (443 if parsed.scheme == "https" else 80),"path":parsed.path or "/","ips":ips,"dns":{"status":"available","records":"Resolved A/AAAA addresses only"},"tls":{"status":"not_checked","note":"TLS certificate inspection is available only through the configured safe probe."},"reputation":{"status":"Data unavailable","providers":[]},"indicators":indicators,"limitations":["No external reputation provider is configured.","No content was downloaded by the local analyzer."]}

def analyze_file(filename: str, content: bytes) -> dict:
    if len(content) > get_settings().max_upload_bytes:
        raise ValueError(f"File exceeds {get_settings().max_upload_bytes} byte limit")
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    indicators = []
    if b"AutoOpen" in content or b"vbaProject" in content:
        indicators.append({"severity":"high","title":"Macro marker detected","evidence":"Static byte scan found a macro marker","recommendation":"Do not enable macros; inspect in a sandbox."})
    if b"<script" in content.lower() and mime in {"text/html", "application/xhtml+xml"}:
        indicators.append({"severity":"medium","title":"Script content detected","evidence":"Static content contains a script tag","recommendation":"Review script origin before opening."})
    return {"filename":filename,"mime_type":mime,"size":len(content),"sha256":sha256,"sha1":sha1,"md5":md5,"indicators":indicators,"reputation":{"status":"Data unavailable","providers":[]},"limitations":["Static analysis only; uploaded content was never executed.","No external hash reputation provider is configured."]}

def analyze_email(content: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(content)
    text = "\n".join(part.get_content() if part.get_content_type() == "text/plain" else "" for part in message.walk()) if message.is_multipart() else (message.get_content() if message.get_content_type() == "text/plain" else "")
    links = re.findall(r"https?://[^\s<>\"']+", text)
    from_addr, reply_to, return_path = message.get("From"), message.get("Reply-To"), message.get("Return-Path")
    indicators = []
    if reply_to and from_addr and reply_to.split("@")[-1].strip(">") != from_addr.split("@")[-1].strip(">"):
        indicators.append({"severity":"medium","title":"Reply-To domain mismatch","evidence":f"From={from_addr}; Reply-To={reply_to}","recommendation":"Verify the sender through a trusted channel."})
    return {"headers":{"from":from_addr,"to":message.get("To"),"reply_to":reply_to,"return_path":return_path,"message_id":message.get("Message-ID")},"authentication":{"authentication_results":message.get("Authentication-Results") or "Data unavailable","spf":"unknown","dkim":"unknown","dmarc":"unknown"},"links":sorted(set(links)),"attachments":[{"filename":part.get_filename(),"content_type":part.get_content_type(),"size":len(part.get_payload(decode=True) or b"")} for part in message.iter_attachments()],"indicators":indicators,"limitations":["SPF, DKIM, and DMARC cannot be independently determined from a message without DNS and trusted receiving headers."]}
