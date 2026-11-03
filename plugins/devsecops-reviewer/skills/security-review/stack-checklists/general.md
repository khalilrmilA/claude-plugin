# General checklist (every stack)

## Untrusted sources
- HTTP: path params, query string, body (form, JSON, multipart), headers (incl. `Host`, `X-Forwarded-*`, `Referer`), cookies.
- Uploaded files: name, content type, content, archive entries.
- Data written earlier by users and read back from the DB, cache, queues, or object storage (stored XSS, second-order SQLi).
- Webhooks and third-party API responses; message queue payloads; environment variables in multi-tenant/CI contexts; CLI args in tools run by others.

## Dangerous sinks (any language)
- Query builders fed by string concatenation/formatting (SQL, NoSQL filters, LDAP filters, XPath, GraphQL).
- Process execution through a shell or with user-controlled arguments.
- Template rendering of user-controlled template **source**; HTML output without contextual escaping.
- File system paths built from input (read, write, delete, include, send_file, zip extraction).
- Outbound requests to user-controlled URLs/hosts (SSRF), redirects to user-controlled URLs.
- XML parsers with external entities/DTDs enabled; YAML/pickle/Java/PHP/.NET deserialization of untrusted data.
- `eval`-like APIs, dynamic imports/requires, reflection driven by input.
- Crypto: MD5/SHA1 for passwords or signatures, ECB mode, static IVs, `Math.random`/`random` for tokens, disabled TLS verification.
- Logging of passwords, tokens, session ids, card numbers, full request bodies with personal data.

## Access control on every new or changed entry point
- Authentication required unless it is explicitly public.
- Authorization: role/permission check for privileged actions; object ownership check for any id taken from the request.
- State-changing actions protected against CSRF when cookie-authenticated.

## Business logic
- Server-side validation of amounts, quantities, prices, discounts, states; never trust totals or prices from the client.
- Multi-step flows enforce order (can't confirm before paying, can't skip verification).
- Concurrency: check-then-act on balances, stock, coupons, unique usernames.

## Config and secrets
- No credentials, tokens, private keys or connection strings with passwords in code, config, tests, Dockerfiles or CI files.
- Debug modes, verbose errors, permissive CORS, insecure cookies and missing security headers in production config.
