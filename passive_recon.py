import os
import whois
import dns.resolver
import requests
import json
import ssl
import socket

# -------------------
# Config
# -------------------
domain = "ai-centre.pk"
findings_dir = "findings"

if not os.path.exists(findings_dir):
    os.makedirs(findings_dir)

# -------------------
# 1) WHOIS
# -------------------
try:
    w = whois.whois(domain)
    with open(f"{findings_dir}/whois.txt", "w", encoding="utf-8") as f:
        f.write(str(w))
    print("[+] WHOIS data saved")
except Exception as e:
    print("[-] WHOIS error:", e)

# -------------------
# 2) DNS Records
# -------------------
records = {}
for rtype in ["A", "MX", "TXT"]:
    try:
        answers = dns.resolver.resolve(domain, rtype)
        records[rtype] = [str(r) for r in answers]
    except Exception as e:
        records[rtype] = f"Error: {e}"

with open(f"{findings_dir}/dns_records.json", "w") as f:
    json.dump(records, f, indent=2)
print("[+] DNS records saved")

# -------------------
# 3) robots.txt
# -------------------
try:
    r = requests.get(f"https://{domain}/robots.txt", timeout=5)
    with open(f"{findings_dir}/robots.txt", "w", encoding="utf-8") as f:
        f.write(r.text)
    print("[+] robots.txt saved")
except Exception as e:
    print("[-] robots.txt error:", e)

# -------------------
# 4) sitemap.xml
# -------------------
try:
    r = requests.get(f"https://{domain}/sitemap.xml", timeout=5)
    with open(f"{findings_dir}/sitemap.xml", "w", encoding="utf-8") as f:
        f.write(r.text)
    print("[+] sitemap.xml saved")
except Exception as e:
    print("[-] sitemap.xml error:", e)

# -------------------
# 5) SSL Certificate Info
# -------------------
try:
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.connect((domain, 443))
        cert = s.getpeercert()
    with open(f"{findings_dir}/ssl_cert.json", "w") as f:
        json.dump(cert, f, indent=2)
    print("[+] SSL certificate info saved")
except Exception as e:
    print("[-] SSL cert error:", e)

# -------------------
# 6) crt.sh Subdomains
# -------------------
try:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = requests.get(url, timeout=10)
    data = r.json()
    subs = set()
    for entry in data:
        name = entry.get("name_value")
        if name:
            for sub in name.split("\n"):
                if domain in sub:
                    subs.add(sub.strip())
    with open(f"{findings_dir}/subdomains.txt", "w") as f:
        f.write("\n".join(sorted(subs)))
    print(f"[+] Found {len(subs)} subdomains (saved)")
except Exception as e:
    print("[-] Subdomain enumeration error:", e)
