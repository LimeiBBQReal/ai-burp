import requests

ips = []
for _ in range(3):
    try:
        r = requests.get('https://api.ipify.org?format=json', timeout=8)
        ips.append(r.json().get('ip'))
    except Exception as e:
        ips.append(f'ERR: {e}')
print('直接出口 IP:', ips)

try:
    r = requests.get('https://ipapi.co/json/', timeout=10)
    d = r.json()
    city = d.get('city')
    country = d.get('country_name')
    ccode = d.get('country_code')
    org = d.get('org')
    asn = d.get('asn')
    print('地理位置: city=' + str(city) + ', country=' + str(country) + ' (' + str(ccode) + '), org=' + str(org) + ', asn=' + str(asn))
except Exception as e:
    print('geo ERR:', e)

try:
    r = requests.get('https://ipinfo.io/json', timeout=10)
    d = r.json()
    print('ipinfo:   city=' + str(d.get('city')) + ', country=' + str(d.get('country')) + ', org=' + str(d.get('org')) + ', loc=' + str(d.get('loc')) + ', tz=' + str(d.get('timezone')))
except Exception as e:
    print('ipinfo ERR:', e)