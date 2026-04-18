# analyze_headers.py

HTTP response header analyzer.

This script sends a request to a URL, prints response headers, then reports:
- Security score
- Positive findings
- Warnings
- Fix suggestions

## Recommended Minimum Production Headers

Use this as a quick checklist for public web apps:
- Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
- Strict-Transport-Security: max-age=31536000; includeSubDomains
- X-Content-Type-Options: nosniff
- X-Frame-Options: SAMEORIGIN (or DENY)
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy: camera=(), microphone=(), geolocation=()
- Remove or minimize: Server
- Remove: X-Powered-By
- Sensitive responses: Cache-Control: no-store, max-age=0

## Run

python3 analyze_headers.py <url>

Examples:

python3 analyze_headers.py https://google.com
python3 analyze_headers.py https://google.com --method HEAD
python3 analyze_headers.py https://google.com --json

## Why It Helps

It quickly shows missing hardening headers such as:
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

It also highlights exposure headers like:
- Server
- X-Powered-By

## Framework Fix Snippets

### Next.js (next.config.js)

```js
/** @type {import('next').NextConfig} */
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
]

const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}

module.exports = nextConfig
```

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Cache-Control "no-store, max-age=0" always;

    server_tokens off;
}
```

### Apache (.htaccess or vhost)

```apache
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set Cache-Control "no-store, max-age=0"
    Header unset X-Powered-By
</IfModule>

ServerTokens Prod
ServerSignature Off
```

## Verify Changes

After applying header changes, rerun:

python3 analyze_headers.py https://your-domain.com

Use the score and warnings to confirm improvement.
