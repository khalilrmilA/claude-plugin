# PHP checklist (plain PHP, Laravel, Symfony, WordPress)

## Injection and XSS
- `mysqli_query($c, "... $_GET[id]")`, `$pdo->query("..." . $x)`, Laravel `DB::raw/whereRaw/selectRaw/orderByRaw` with interpolation, Doctrine DQL string concatenation → SQLi. Safe: `prepare` + `bind_param`/`execute([$x])`, Eloquent/Query Builder bindings.
- `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks with input → command injection. `escapeshellarg` on each argument is required; `escapeshellcmd` alone is not enough.
- `echo $_GET['x']`, `<?= $x ?>` without `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`; Blade `{!! $x !!}`; Twig `|raw` → XSS. Blade `{{ }}` and Twig `{{ }}` escape by default.
- `include/require/include_once($_GET['page'] . '.php')` → LFI (and RFI if `allow_url_include`). `file_get_contents`, `readfile`, `fopen` with user paths → path traversal. Safe: allowlist map, `basename` + realpath containment.
- `unserialize($_COOKIE[...])`/on request data → object injection (POP chains). Safe: `json_decode`, or `unserialize($x, ['allowed_classes' => false])`.
- `simplexml_load_string`, `DOMDocument::loadXML` with `LIBXML_NOENT`/`LIBXML_DTDLOAD` → XXE.
- `curl_setopt($ch, CURLOPT_URL, $_GET['url'])`, `file_get_contents($url)` → SSRF. `header("Location: " . $_GET['r'])` → open redirect.
- `eval`, `assert` with strings, `preg_replace` with `/e`, `create_function`, variable functions `$f()` from input → code injection.
- `extract($_POST)`, `parse_str` without a target array → variable overwrite.
- Uploads: `move_uploaded_file` with the client filename, no extension/MIME allowlist, stored in a web-executable directory (`.php` upload = RCE), relying on `$_FILES['type']`.
- LDAP: `ldap_search($ds, $dn, "(uid=$user)")` without `ldap_escape` → LDAP injection.

## Auth and access control
- Pages/routes missing the auth check or `auth` middleware used elsewhere; Laravel routes outside the `auth` group; missing `$this->authorize()` / policies / `Gate::allows`.
- Records fetched by id without `where('user_id', auth()->id())` → IDOR.
- `$request->all()` into `create()/update()` with `$guarded = []` → mass assignment (`is_admin`, `role`).
- Passwords with `md5()`, `sha1()`, `crypt` without proper salt. Safe: `password_hash()` / `password_verify()`, Laravel `Hash::make`.
- Loose comparison `==` on tokens/hashes (`"0e123" == "0e456"` is true) → auth bypass; use `hash_equals`.
- `session_regenerate_id()` missing after login → session fixation.

## Config
- `display_errors=On`, `APP_DEBUG=true`, `error_reporting(E_ALL)` printing to users in production config.
- `.env` committed with `APP_KEY`, DB passwords; credentials in `config/*.php`.
- `setcookie` without `secure`, `httponly`, `samesite` for session cookies; `session.cookie_secure=0`.
- `header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN'])` with credentials.
- `rand()`, `mt_rand()`, `uniqid()` for tokens. Safe: `random_bytes`, `random_int`.
