import os
import requests
import nmap
import json

domain = "ai-centre.pk"
findings_dir = "findings"

if not os.path.exists(findings_dir):
    os.makedirs(findings_dir)

# -------------------
# 1) Light Port Scan (Only 80, 443, 8080)
# -------------------
try:
    nm = nmap.PortScanner()
    nm.scan(domain, '80,443,8080', arguments='-Pn -T2')
    with open(f"{findings_dir}/ports.json", "w") as f:
        json.dump(nm[domain], f, indent=2)
    print("[+] Port scan completed (saved to ports.json)")
except Exception as e:
    print("[-] Port scan error:", e)

# -------------------
# 2) HTTP Headers
# -------------------
try:
    r = requests.get(f"https://{domain}", timeout=5)
    with open(f"{findings_dir}/headers.json", "w") as f:
        json.dump(dict(r.headers), f, indent=2)
    print("[+] HTTP headers saved")
except Exception as e:
    print("[-] HTTP headers error:", e)

# -------------------
# 3) Clickjacking Test (local HTML file)
# -------------------
try:
    html_code = f"""<!doctype html>
<html>
<body>
<h2>Clickjacking Test for {domain}</h2>
<iframe src="https://{domain}" width="1024" height="800"></iframe>
</body>
</html>
"""
    with open(f"{findings_dir}/clickjacking_test.html", "w", encoding="utf-8") as f:
        f.write(html_code)
    print("[+] Clickjacking PoC HTML created (open locally to test)")
except Exception as e:
    print("[-] Clickjacking PoC error:", e)

# -------------------
# 4) Directory listing check (common paths)
# -------------------
common_paths = ["/uploads/", "/images/", "/backup/", "/files/"]
dir_results = {}
for path in common_paths:
    url = f"https://{domain}{path}"
    try:
        r = requests.get(url, timeout=5)
        if "Index of" in r.text:
            dir_results[path] = "Possible directory listing"
        else:
            dir_results[path] = "No listing"
    except Exception as e:
        dir_results[path] = f"Error: {e}"

with open(f"{findings_dir}/dir_listing.json", "w") as f:
    json.dump(dir_results, f, indent=2)
print("[+] Directory listing check completed")
