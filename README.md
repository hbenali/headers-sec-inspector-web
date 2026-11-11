# Security Headers Grader

A free, single-page HTTP security headers grader and generator. Live at [headers-sec.hbenali.ovh](https://headers-sec.hbenali.ovh).

No backend, no build step, no dependencies, no network calls: static HTML, CSS and one small script. A browser cannot read another site's response headers (CORS), so you **paste** the headers (from `curl -sI https://example.com` or the browser dev tools) and the page grades them locally. The page's CSP is `connect-src 'none'`.

## Features

- **Grade A+ to F** with a score out of 100, a per-header result and a fix hint. The scoring is a heuristic (a weighted checklist), not an audit.
- **Content-Security-Policy**: parses directives, flags `unsafe-inline`, `unsafe-eval`, wildcard and scheme sources, missing `default-src`, `object-src`, `base-uri`, `frame-ancestors`; report-only is not counted as enforcement
- **Strict-Transport-Security**: max-age of at least a year, `includeSubDomains`, `preload`
- **X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP**
- **X-Frame-Options** versus CSP `frame-ancestors`
- **Cache-Control** (graded when you mark the page as sensitive)
- **Set-Cookie** flags: `Secure`, `HttpOnly`, `SameSite`, `__Host-` and `__Secure-` prefix rules
- **Information leaks**: `Server` with a version, `X-Powered-By`, `X-AspNet-Version`
- **Tolerant parser**: HTTP/1.1 and HTTP/2 dumps, optional status line, lower-case names, repeated headers, folded values, redirect chains (the last response is graded), `curl -v` output
- **Generator** for nginx, Apache, Caddy and a `_headers` file (Cloudflare Pages, Netlify)
- `?domain=example.com` fills in the exact `curl` command to copy
- Dark editorial design with a light mode, self-hosted fonts, PWA, strict CSP

## Running locally

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

The grading logic is a plain script that also exports its functions under Node, which is how it is tested:

```bash
node -e "const A=require('./app.js'); console.log(A.grade(A.parseHeaders('HTTP/2 200\nx-content-type-options: nosniff'), {}).grade)"
```

## Deployment

GitHub Pages, deployed on every push to `main` (see `.github/workflows/`).

## License

MIT, see [LICENSE](LICENSE).
