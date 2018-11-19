import subprocess
import tempfile
from ipwhois import IPWhois
import json

# netstat_output = sp.run(['netstat', '-a'], stdout=sp.PIPE).stdout.decode('utf-8').split("\n")

with tempfile.TemporaryFile() as tempf:
    proc = subprocess.Popen(['netstat', '-a'], stdout=tempf)
    proc.wait()
    tempf.seek(0)

    out = tempf.read().decode('utf-8').split('\n')

# with open('tmp.txt', 'r') as f:
#     out = f.read().split('\n')
    cells = []
    for line in out:
        res = ""
        for c in line:
            if not res.endswith(c):
                res += c
        cells.append(res.split(' '))

    #ips = [r[4] for r in cells if r[4] and ':' in r[4]]

    ips = []
    for r in cells:
        if len(r) < 4:
            break
        if ':' in r[4]:
            ips.append(r[4])

    ips = set(ips)

    with open("result.txt", "w") as of:
        for ip in ips:
            ip = ip.split(':')[0]
            of.write("%s IP: %s" %("\n" * 3 + "#"*5, ip))
            try:
                res = IPWhois(ip)
                res = res.lookup_whois()
                city = res['nets'][0]['city']
                corp = res['nets'][0]['name']
                email = res['nets'][0]['emails'][0]

                of.write("\n\tCorp:\t%s\n\tCity:\t%s\n\tEmail:\t%s" %(corp, city, email))
            except:
                of.write("\n--Not a valid IP")
                pass
            
            

