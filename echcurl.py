#!/usr/bin/env python3
import sys, subprocess, argparse, socket
from urllib.parse import urlsplit

def get_ech(domain, resolver="1.1.1.1"):
    r = subprocess.run(["dig", "+short", "HTTPS", domain, f"@{resolver}"],
                        capture_output=True, text=True)
    for line in r.stdout.splitlines():
        for tok in line.split():
            if tok.startswith("ech="):
                v = tok[4:]
                v += "=" * (-len(v) % 4)
                return v
    return None

def main():
    ap = argparse.ArgumentParser(add_help=True, description="curl-like ECH request tool")
    ap.add_argument("url")
    ap.add_argument("-X", "--request", default=None, help="HTTP method")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header, repeatable")
    ap.add_argument("-d", "--data", default=None, help="request body")
    ap.add_argument("-A", "--user-agent", default="Mozilla/5.0 (X11; Linux x86_64)")
    ap.add_argument("-b", "--cookie", default=None)
    ap.add_argument("--outer-sni", default=None, help="value for -ech_outer_sni")
    ap.add_argument("--no-outer-sni", action="store_true")
    ap.add_argument("--no-ech", action="store_true", help="send plaintext SNI (for comparison)")
    ap.add_argument("--resolver", default="1.1.1.1")
    ap.add_argument("-i", "--include", action="store_true", default=True)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    u = urlsplit(args.url if "://" in args.url else "https://" + args.url)
    host = u.hostname
    port = u.port or 443
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    method = args.request or ("POST" if args.data else "GET")

    headers = [f"Host: {host}", f"User-Agent: {args.user_agent}", "Accept: */*",
               "Accept-Encoding: identity"]
    if args.cookie:
        headers.append(f"Cookie: {args.cookie}")
    for h in args.header:
        headers.append(h)

    body = args.data or ""
    if body and not any(h.lower().startswith("content-type:") for h in headers):
        headers.append("Content-Type: application/x-www-form-urlencoded")
    if body or method in ("POST", "PUT", "PATCH"):
        headers.append(f"Content-Length: {len(body.encode())}")
    headers.append("Connection: close")

    req = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body
    req_bytes = req.encode()

    cmd = ["docker", "run", "--rm", "-i", "openssl-ech", "openssl", "s_client",
           "-connect", f"{host}:{port}", "-tls1_3", "-servername", host, "-quiet"]

    if not args.no_ech:
        ech = get_ech(host, args.resolver)
        if not ech:
            print(f"[!] no ECH record for {host}", file=sys.stderr)
            sys.exit(1)
        cmd += ["-ech_config_list", ech]
        if args.outer_sni:
            cmd += ["-ech_outer_sni", args.outer_sni]
        if args.no_outer_sni:
            cmd += ["-ech_no_outer_sni"]

    if args.verbose:
        print("--- REQUEST ---", file=sys.stderr)
        print(req, file=sys.stderr)
        print("--- CMD ---", file=sys.stderr)
        print(" ".join(cmd), file=sys.stderr)

    p = subprocess.run(cmd, input=req_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.stdout.buffer.write(p.stdout)
    if args.verbose:
        sys.stderr.buffer.write(p.stderr)

if __name__ == "__main__":
    main()
