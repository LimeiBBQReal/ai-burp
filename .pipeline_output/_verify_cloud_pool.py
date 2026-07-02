import requests

urls = ['http.enc', 'socks5.enc', 'meta.enc']
for f in urls:
    url = f'https://raw.githubusercontent.com/LimeiBBQReal/proxy-pool/main/alive/{f}'
    try:
        r = requests.get(url, timeout=15)
        size = len(r.content)
        ct = r.headers.get('Content-Type', '?')
        preview = r.content[:32].hex() if r.content else ''
        print(f'{f}: status={r.status_code} size={size} bytes type={ct}')
        if r.status_code == 200 and r.content:
            print(f'  hex preview: {preview}')
    except Exception as e:
        print(f'{f}: ERROR {e}')