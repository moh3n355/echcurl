# echcurl

License: MIT

`echcurl` is a curl-like command-line tool for sending HTTP requests over TLS 1.3 with **Encrypted Client Hello (ECH)**, built for pentesting and bug bounty use. It fetches the target's `ECHConfigList` from its DNS `HTTPS` record, then sends the request through an ECH-capable `openssl s_client` running in Docker (Ubuntu's stock `curl`/`openssl` do not support ECH yet).

Before sending anything, `echcurl` checks that `docker`, `dig`, and the local `openssl-ech` Docker image are actually available, and exits with a clear message instead of failing halfway through a request.

> **Why not just `curl`?** Mainstream `curl`/`openssl` builds (including Ubuntu's) don't support ECH out of the box. Building `curl` itself with ECH is a heavier, more fragile build than building `openssl` alone, so `echcurl` builds `openssl` (with ECH support baked in since 4.0) inside a small Docker image and drives `openssl s_client` directly.

## Resources

- [Usage](#usage)
- [Flags](#flags)
- [Requirements](#requirements)
- [Installation](#installation)
- [Limitations](#limitations)

## Usage

Examples:
```
$ echcurl example.com
$ echcurl -X POST -d "user=admin&pass=test" example.com/login
$ echcurl -H "Authorization: Bearer TOKEN" example.com/api
$ echcurl -H "Content-Type: application/json" -d '{"a":1}' example.com/api
$ echcurl -b "session=abc123; theme=dark" example.com
$ echcurl -L example.com/old-path
$ echcurl -I example.com
$ echcurl --body-only example.com -o body.html
$ echcurl -x 127.0.0.1:8080 example.com
$ echcurl --no-ech example.com
$ echcurl --outer-sni cloudflare-ech.com example.com
$ echcurl -v example.com
```

To display help for the tool use the `-h` flag:
```
$ echcurl -h
```

## Flags

| Flag | Description | Example |
|---|---|---|
| `-X`, `--request` | HTTP method. Defaults to `GET`, or `POST` automatically if `-d` is given | `echcurl -X PUT example.com` |
| `-H`, `--header` | extra request header, repeatable | `echcurl -H "X-Test: 1" -H "X-Foo: bar" example.com` |
| `-d`, `--data` | request body (raw string). Sets `Content-Type: application/x-www-form-urlencoded` unless overridden with `-H` | `echcurl -d "a=1&b=2" example.com` |
| `-A`, `--user-agent` | custom `User-Agent` (default: a generic desktop Chrome-like UA) | `echcurl -A "curl/8.0" example.com` |
| `-b`, `--cookie` | sets the `Cookie` header | `echcurl -b "session=abc123" example.com` |
| `-x`, `--proxy` | route the connection through an HTTP CONNECT proxy (`host:port`) | `echcurl -x 127.0.0.1:8080 example.com` |
| `-L`, `--location` | follow `3xx` redirects (`Location` header), each hop re-resolves ECH for the new host | `echcurl -L example.com/old` |
| `--max-redirects` | maximum redirects to follow with `-L` (default: `10`) | `echcurl -L --max-redirects 3 example.com` |
| `-o`, `--output` | write the response to a file instead of stdout | `echcurl example.com -o out.html` |
| `-I`, `--headers-only` | print only the status line and response headers | `echcurl -I example.com` |
| `--body-only` | print only the response body, de-chunked if `Transfer-Encoding: chunked` | `echcurl --body-only example.com` |
| `--outer-sni` | override the outer (unencrypted) SNI value | `echcurl --outer-sni cloudflare-ech.com example.com` |
| `--no-outer-sni` | omit the SNI extension from the outer ClientHello entirely | `echcurl --no-outer-sni example.com` |
| `--no-ech` | send a normal, plaintext-SNI TLS request (no ECH) — useful for A/B comparison | `echcurl --no-ech example.com` |
| `--resolver` | DNS resolver used to fetch the `HTTPS` record (default: `1.1.1.1`) | `echcurl --resolver 8.8.8.8 example.com` |
| `--timeout` | per-connection timeout in seconds (default: `20`) | `echcurl --timeout 40 example.com` |
| `--retries` | retry attempts on DNS/connection failure before giving up (default: `3`) | `echcurl --retries 5 example.com` |
| `--delay` | base backoff delay in seconds between retries (default: `1.0`) | `echcurl --delay 2 example.com` |
| `-v`, `--verbose` | print the raw outgoing request, the underlying `docker`/`openssl` command, and retry/redirect diagnostics | `echcurl -v example.com` |
| `-h`, `--help` | show help and exit | `echcurl -h` |

If the target has no ECH DNS record, `echcurl` prints `no ECH record for <domain>` and exits without sending anything, unless `--no-ech` was passed.

## Requirements

- [Docker](https://docs.docker.com/engine/install/) — runs the ECH-capable `openssl` build
- `dig` (from `dnsutils` / `bind-utils`) — fetches the `HTTPS` DNS record
- `python3` — runs `echcurl` itself

`echcurl` checks for all three (plus the `openssl-ech` Docker image and daemon reachability) before doing any network work, and exits with a specific fix-it message if something's missing — it never sends a partial or silently-broken request.

## Installation

From source:
```
$ git clone https://github.com/<your-username>/echcurl.git
$ cd echcurl
$ ./install.sh
```

`install.sh` builds the `openssl-ech` Docker image (OpenSSL built from source with ECH support, ~5-10 minutes the first time) and installs `echcurl` to `/usr/local/bin`.

On a domain-fronting-style target where you need to point at a different OpenSSL branch/tag, rebuild manually:
```
$ docker build --build-arg REF=openssl-4.0.3 -t openssl-ech .
```

## Limitations

- **HTTP/1.1 only** — no HTTP/2 or HTTP/3, since `openssl s_client` doesn't speak HTTP framing itself.
- **No TLS session reuse / keep-alive** — every request opens a fresh TLS connection.
- **No multipart/form-data or file uploads** — `-d` only sends a raw string body.
- **No cookie jar** — `-b` sets a static `Cookie` header per request; no automatic storage across redirects.
- Requires the target to actually publish ECH (`ech=` in its `HTTPS` DNS record); `echcurl` will not silently fall back to plaintext SNI unless `--no-ech` is explicit.
