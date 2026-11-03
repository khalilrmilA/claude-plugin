# Django checklist

## Injection and XSS
- `raw()`, `extra()`, `RawSQL`, `cursor.execute()` with f-strings, `%` or `.format()` → SQLi. Safe: `cursor.execute(sql, params)`, ORM filters.
- `mark_safe()`, `|safe`, `{% autoescape off %}`, `format_html` misuse, `SafeString` on user data → XSS.
- `Template(user_input).render()` → template injection.
- `subprocess` with `shell=True`, `os.system`, `os.popen` → command injection.
- `pickle.loads`, `yaml.load` (non-safe loader), `signing.loads` with a leaked key → deserialization.
- `open()/FileResponse/send_file` with joined user paths; check `os.path.realpath` stays under the base dir.
- `requests.get(user_url)` → SSRF; `redirect(request.GET['next'])` without `url_has_allowed_host_and_scheme` → open redirect.
- `lxml.etree.XMLParser(resolve_entities=True)`, `xml.dom.minidom` on untrusted XML → prefer `defusedxml`.

## Auth and access control
- Views without `@login_required` / `LoginRequiredMixin` / DRF `permission_classes` (check `DEFAULT_PERMISSION_CLASSES`; `AllowAny` on sensitive views).
- `Model.objects.get(pk=request.GET['id'])` without filtering by `request.user` → IDOR. Safe: `get_object_or_404(Order, pk=pk, owner=request.user)`.
- Admin-only logic gated by a client-sent flag instead of `request.user.is_staff` / permissions.
- DRF serializers with `fields = '__all__'` on writable models → mass assignment (`is_staff`, `role`, `owner`).
- `@csrf_exempt` on cookie-authenticated, state-changing views.
- Custom password hashing instead of `make_password`; `PASSWORD_HASHERS` with MD5/SHA1 first.

## Settings
- `DEBUG = True` or `DEBUG = os.environ.get(..., True)` defaulting to true; `ALLOWED_HOSTS = ['*']`.
- `SECRET_KEY` literal in settings (anything not read from env/secret store).
- `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` false/missing in production; `SESSION_COOKIE_HTTPONLY = False`.
- `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS`, `SECURE_CONTENT_TYPE_NOSNIFF` missing.
- `CORS_ALLOW_ALL_ORIGINS = True` / `CORS_ORIGIN_ALLOW_ALL` with `CORS_ALLOW_CREDENTIALS = True`.
- Logging config that logs `request.POST` or headers with credentials.
