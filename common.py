import ipaddress, re

TOP_PORTS = [21,22,23,25,53,80,110,135,139,143,389,443,445,587,993,995,
             1433,1521,3306,3389,5432,5900,6379,8080,9000]

SERVICE_MAP = {
    21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
    135:"msrpc",139:"netbios",143:"imap",389:"ldap",443:"https",445:"smb",
    587:"smtp",993:"imaps",995:"pop3s",1433:"mssql",1521:"oracle",3306:"mysql",
    3389:"rdp",5432:"postgres",5900:"vnc",6379:"redis",8080:"http-alt"
}

def parse_hosts(s: str):
    items = [x.strip() for x in s.split(",") if x.strip()]
    # keep order but de-dupe
    return list(dict.fromkeys(items))

def validate_host(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        # loose but practical hostname regex
        return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?", h))

def parse_ports(mode: str, custom: str = ""):
    m = mode.lower()
    if m == "quick": return TOP_PORTS[:]
    if m == "full":  return list(range(1, 1025))
    # custom
    out = set()
    for token in [t.strip() for t in custom.split(",") if t.strip()]:
        if "-" in token:
            a,b = token.split("-",1)
            a,b = int(a), int(b)
            out.update(range(min(a,b), max(a,b)+1))
        else:
            out.add(int(token))
    return sorted([p for p in out if 1 <= p <= 65535])

