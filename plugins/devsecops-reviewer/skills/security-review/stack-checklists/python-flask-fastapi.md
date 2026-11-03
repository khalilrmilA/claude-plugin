# Flask / FastAPI checklist

## Injection and XSS
- `cursor.execute(f"...{x}")`, `"..." % x`, `.format(x)`, SQLAlchemy `text(f"...")` / `engine.execute(string)` → SQLi. Safe: bound params `text("... :id"), {"id": x}`, ORM.
- PyMongo filters built from `request.json` without type checks (`{"$ne": null}`, `$where`) → NoSQL injection.
- `render_template_string(user_input)` or building a template from input → SSTI (Jinja2 → RCE).
- `Markup(user)`, `|safe`, returning HTML strings with f-strings, `make_response("<p>" + x)` → XSS. Jinja autoescape is on for `.html` templates only.
- `subprocess.*(..., shell=True)`, `os.system`, `os.popen` with input → command injection. Safe: argument list, no shell, allowlisted values.
- `send_file(os.path.join(base, name))`, `open(base + name)` → path traversal. Safe: `send_from_directory`, `werkzeug.utils.secure_filename`, realpath containment check.
- `requests.get(request.args['url'])`, `urllib.request.urlopen(x)` → SSRF. Look for allowlists and blocking of private/link-local/metadata addresses (after DNS resolution).
- `redirect(request.args.get('next'))` → open redirect.
- `pickle.loads`, `yaml.load` without `SafeLoader`, `jsonpickle.decode`, `marshal` on request data or cookies → deserialization RCE.
- `lxml` with `resolve_entities=True` / `XMLParser(load_dtd=True)`, `xml.sax` with external entities → XXE; prefer `defusedxml`.
- Uploads: `file.save(os.path.join(UPLOAD, file.filename))` without `secure_filename`, no extension/content allowlist, saved under a served static path.

## Auth and access control
- Routes missing `@login_required` / FastAPI `Depends(get_current_user)`; compare with sibling routes.
- Role checks read from `request.json["role"]`, a header, or an unsigned cookie.
- Object fetched by id without `owner_id == current_user.id` → IDOR.
- `jwt.decode(token, options={"verify_signature": False})`, `algorithms` missing or including `none`, secret hardcoded/short.
- `session` with a hardcoded `app.secret_key` → forged sessions.
- Passwords hashed with `hashlib.md5/sha1/sha256` (unsalted, fast). Safe: `werkzeug.security.generate_password_hash`, `bcrypt`, `argon2`.
- Login without rate limiting / lockout (`flask-limiter`, `slowapi`).
- Token comparison with `==` instead of `hmac.compare_digest` (low).

## Config
- `app.run(debug=True)`, `app.debug = True`, `FLASK_DEBUG=1` in committed config → Werkzeug debugger = RCE if exposed.
- `CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)`; FastAPI `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`.
- `SESSION_COOKIE_SECURE`/`HTTPONLY`/`SAMESITE` not set for production; `set_cookie(..., httponly=False)` on session tokens.
- No security headers (Talisman/secure middleware) on apps serving HTML.
- `logging.info(f"login {username} {password}")`, logging full `request.json` or `Authorization` headers.
