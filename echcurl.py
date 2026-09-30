#!/usr/bin/env python3
"""
echcurl - curl-like tool for sending HTTP requests over TLS with
Encrypted Client Hello (ECH), for pentesting / bug bounty use.

Requires:
  - docker (with the 'openssl-ech' image built via install.sh)
  - dig (dnsutils)
  - python3
"""
import sys
import subprocess
import argparse
import shutil
import time
from urllib.parse import urlsplit

DOCKER_IMAGE = "openssl-ech"
DEFAULT_RESOLVER = "1.1.1.1"


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

def check_dependencies():
    missing = []
    checks = [
        ("docker", "install Docker: https://docs.docker.com/engine/install/"),
        ("dig", "install dnsutils: sudo apt install dnsutils  (or: yum install bind-utils)"),
    ]
    for tool, hint in checks:
        if shutil.which(tool) is None:
            missing.append(f"  - '{tool}' not found. {hint}")

    if missing:
        print("[!] Missing required dependencies:", file=sys.stderr)
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)

    r = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                        capture_output=True)
    if r.returncode != 0:
        print(f"[!] Docker image '{DOCKER_IMAGE}' was not found.", file=sys.stderr)
        print("    Build it first by running ./install.sh from the repo root.",
              file=sys.stderr)
        sys.exit(1)

    r = subprocess.run(["docker", "info"], capture_output=True)
    if r.returncode != 0:
        print("[!] Docker daemon is not reachable (is it running? "
              "do you have permission to use it?).", file=sys.stderr)
        print("    Try: sudo systemctl start docker   or add your user to the 'docker' group.",
              file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# ECH config retrieval (with retry)
# ---------------------------------------------------------------------------

def get_ech(domain, resolver, retries, delay, verbose):
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            r = subprocess.run(
                ["dig", "+short", "HTTPS", domain, f"@{resolver}", "+time=5", "+tries=1"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode != 0:
                last_err = r.stderr.strip() or f"dig exited with code {r.returncode}"
            else:
                for line in r.stdout.splitlines():
                    for tok in line.split():
                        if tok.startswith("ech="):
                            v = tok[4:]
                            v += "=" * (-len(v) % 4)
                            return v
                return None  # dig succeeded but no ech= field -> domain has no ECH record
        except subprocess.TimeoutExpired:
            last_err = "dig timed out"
        except Exception as e:
            last_err = str(e)

        if verbose:
            print(f"[!] dig attempt {attempt}/{retries} failed: {last_err}", file=sys.stderr)
        if attempt < retries:
            time.sleep(delay * attempt)

    print(f"[!] Could not query DNS for {domain} after {retries} attempt(s): {last_err}",
          file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# HTTP response parsing (status line, headers, body incl. chunked decoding)
# ---------------------------------------------------------------------------

def dechunk(body: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        j = body.find(b"\r\n", i)
        if j == -1:
            break
        size_line = body[i:j].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        out += body[start:start + size]
        i = start + size + 2  # skip chunk data + trailing CRLF
    return bytes(out)


def parse_response(raw: bytes):
    if b"\r\n\r\n" in raw:
        head, _, body = raw.partition(b"\r\n\r\n")
    elif b"\n\n" in raw:
        head, _, body = raw.partition(b"\n\n")
    else:
        head, body = raw, b""

    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    status_line = lines[0].decode(errors="replace") if lines else ""
    headers = {}
    for l in lines[1:]:
        if b":" in l:
            k, _, v = l.partition(b":")
            headers[k.decode(errors="replace").strip()] = v.decode(errors="replace").strip()

    if headers.get("Transfer-Encoding", "").lower() == "chunked":
        body = dechunk(body)

    return status_line, headers, body


# ---------------------------------------------------------------------------
# Request building / sending
# ---------------------------------------------------------------------------

def build_request(method, host, path, headers_list, body, user_agent, cookie):
    headers = [f"Host: {host}", f"User-Agent: {user_agent}", "Accept: */*",
               "Accept-Encoding: identity"]
    if cookie:
        headers.append(f"Cookie: {cookie}")
    for h in headers_list:
        headers.append(h)

    if body and not any(h.lower().startswith("content-type:") for h in headers):
        headers.append("Content-Type: application/x-www-form-urlencoded")
    if body or method in ("POST", "PUT", "PATCH"):
        headers.append(f"Content-Length: {len(body.encode())}")
    headers.append("Connection: close")

    req = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n" + body
    return req.encode()


def send_once(host, port, req_bytes, ech_config, outer_sni, no_outer_sni,
              no_ech, proxy, timeout, verbose):
    cmd = ["docker", "run", "--rm", "-i", DOCKER_IMAGE, "openssl", "s_client",
           "-connect", f"{host}:{port}", "-tls1_3", "-servername", host, "-quiet"]

    if proxy:
        cmd += ["-proxy", proxy]

    if not no_ech:
        cmd += ["-ech_config_list", ech_config]
        if outer_sni:
            cmd += ["-ech_outer_sni", outer_sni]
        if no_outer_sni:
            cmd += ["-ech_no_outer_sni"]

    if verbose:
        print("--- REQUEST ---", file=sys.stderr)
        print(req_bytes.decode(errors="replace"), file=sys.stderr)
        print("--- CMD ---", file=sys.stderr)
        print(" ".join(cmd), file=sys.stderr)

    try:
        p = subprocess.run(cmd, input=req_bytes, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"connection timed out after {timeout}s"

    if p.returncode != 0 and not p.stdout:
        err = p.stderr.decode(errors="replace").strip()
        return None, err or f"openssl exited with code {p.returncode}"

    return p.stdout, None


def request_with_retry(host, port, req_bytes, ech_config, args):
    last_err = None
    for attempt in range(1, args.retries + 1):
        raw, err = send_once(host, port, req_bytes, ech_config, args.outer_sni,
                              args.no_outer_sni, args.no_ech, args.proxy,
                              args.timeout, args.verbose)
        if raw is not None:
            return raw
        last_err = err
        if args.verbose:
            print(f"[!] attempt {attempt}/{args.retries} failed: {last_err}", file=sys.stderr)
        if attempt < args.retries:
            time.sleep(args.delay * attempt)

    print(f"[!] Request to {host}:{port} failed after {args.retries} attempt(s): {last_err}",
          file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="curl-like tool for HTTP requests over ECH")
    ap.add_argument("url")
    ap.add_argument("-X", "--request", default=None, help="HTTP method (default: GET, or POST if -d given)")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header, repeatable")
    ap.add_argument("-d", "--data", default=None, help="request body")
    ap.add_argument("-A", "--user-agent", default="Mozilla/5.0 (X11; Linux x86_64)")
    ap.add_argument("-b", "--cookie", default=None)
    ap.add_argument("-x", "--proxy", default=None,
                     help="HTTP CONNECT proxy as host:port (requires an openssl s_client "
                          "build with -proxy support)")
    ap.add_argument("-L", "--location", action="store_true", help="follow 3xx redirects")
    ap.add_argument("--max-redirects", type=int, default=10)
    ap.add_argument("-o", "--output", default=None, help="write response to file instead of stdout")
    ap.add_argument("-I", "--headers-only", action="store_true",
                     help="print only the status line and response headers")
    ap.add_argument("--body-only", action="store_true",
                     help="print only the response body (dechunked if needed)")
    ap.add_argument("--outer-sni", default=None, help="value for -ech_outer_sni")
    ap.add_argument("--no-outer-sni", action="store_true")
    ap.add_argument("--no-ech", action="store_true", help="send plaintext SNI (for comparison)")
    ap.add_argument("--resolver", default=DEFAULT_RESOLVER)
    ap.add_argument("--timeout", type=int, default=20, help="per-connection timeout, seconds")
    ap.add_argument("--retries", type=int, default=3, help="retry attempts on network failure")
    ap.add_argument("--delay", type=float, default=1.0, help="base backoff delay, seconds (doubles-ish per attempt)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.headers_only and args.body_only:
        print("[!] -I/--headers-only and --body-only are mutually exclusive", file=sys.stderr)
        sys.exit(1)

    check_dependencies()

    url = args.url if "://" in args.url else "https://" + args.url
    method = args.request or ("POST" if args.data else "GET")
    body = args.data or ""

    seen = set()
    final_raw = b""

    for _ in range(args.max_redirects + 1):
        u = urlsplit(url)
        host = u.hostname
        if host is None:
            print(f"[!] Could not parse a hostname from: {url}", file=sys.stderr)
            sys.exit(1)
        port = u.port or 443
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")

        if url in seen:
            print(f"[!] Redirect loop detected at {url}", file=sys.stderr)
            sys.exit(1)
        seen.add(url)

        ech_config = None
        if not args.no_ech:
            ech_config = get_ech(host, args.resolver, args.retries, args.delay, args.verbose)
            if not ech_config:
                print(f"[!] no ECH record for {host}", file=sys.stderr)
                sys.exit(1)

        req_bytes = build_request(method, host, path, args.header, body,
                                   args.user_agent, args.cookie)
        raw = request_with_retry(host, port, req_bytes, ech_config, args)
        status_line, headers, _ = parse_response(raw)
        final_raw = raw

        status_code = status_line.split(" ")[1] if len(status_line.split(" ")) > 1 else ""

        if args.location and status_code.startswith("3") and "Location" in headers:
            loc = headers["Location"]
            if loc.startswith("http://") or loc.startswith("https://"):
                url = loc
            elif loc.startswith("/"):
                url = f"{u.scheme}://{host}{loc}"
            else:
                base = path.rsplit("/", 1)[0] if "/" in path else ""
                url = f"{u.scheme}://{host}{base}/{loc}"
            if args.verbose:
                print(f"[*] {status_code} redirect -> {url}", file=sys.stderr)
            continue
        break

    # --- select output ---
    status_line, headers, resp_body = parse_response(final_raw)
    if args.headers_only:
        out = status_line + "\r\n" + "\r\n".join(f"{k}: {v}" for k, v in headers.items()) + "\r\n"
        out_bytes = out.encode()
    elif args.body_only:
        out_bytes = resp_body
    else:
        out_bytes = final_raw

    if args.output:
        with open(args.output, "wb") as f:
            f.write(out_bytes)
        print(f"[*] Response written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(out_bytes)


if __name__ == "__main__":
    main()
