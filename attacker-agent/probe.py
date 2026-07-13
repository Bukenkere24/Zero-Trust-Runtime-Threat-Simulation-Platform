import urllib.request

for url in [
    "http://127.0.0.1:5000/health",
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:5001/health",
    "http://127.0.0.1:5002/health",
]:
    try:
        r = urllib.request.urlopen(url, timeout=3)
        print(url, r.status, r.read()[:80])
    except Exception as e:
        print(url, "ERR", e)
