# Go checklist

## Injection and XSS
- `db.Query("..." + x)`, `fmt.Sprintf` into SQL, GORM `.Raw(fmt.Sprintf(...))`, `.Where("name = '" + x + "'")` → SQLi. Safe: `db.Query("... $1", x)`, `.Where("name = ?", x)`.
- `exec.Command("sh", "-c", x)`, `exec.Command("bash", "-c", ...)` → command injection. `exec.Command(bin, args...)` without a shell is safe if `bin` is fixed.
- `text/template` used for HTML (no escaping), `template.HTML(x)`, `template.JS(x)`, `template.URL(x)` on user data → XSS. `html/template` escapes contextually.
- `os.Open(filepath.Join(base, r.URL.Query().Get("f")))` without `filepath.Clean` + prefix check (and `filepath.Join` doesn't stop `..`) → path traversal. Prefer `os.Root`/`http.FS` with `fs.Sub`.
- `http.Get(userURL)` → SSRF; `http.Redirect(w, r, r.URL.Query().Get("next"), 302)` → open redirect.
- `encoding/gob` / `yaml.Unmarshal` into `interface{}` from untrusted sources is usually safe in Go; flag custom reflection-based dispatch on input.
- Zip extraction (`archive/zip`) writing `f.Name` without containment → Zip Slip.

## Auth and access control
- Handlers registered without the auth middleware chain used by siblings (`mux.HandleFunc` vs wrapped handlers).
- Ownership checks missing on `id := chi.URLParam(r, "id")` lookups → IDOR.
- `jwt.Parse` with a keyfunc that doesn't check `token.Method`; `ParseUnverified`; hardcoded HMAC key.
- Passwords hashed with `md5`/`sha1`/`sha256`; safe: `golang.org/x/crypto/bcrypt`, `argon2`.
- Data races on shared maps/balances without mutex (`go test -race` hints) → race conditions.

## Config
- `InsecureSkipVerify: true`; `math/rand` for tokens (use `crypto/rand`); `cors.AllowAll()` with credentials; missing `Secure`/`HttpOnly` on `http.Cookie`; `pprof` handlers exposed (`import _ "net/http/pprof"` on a public mux).
- `log.Printf("%+v", req)` dumping credentials.
