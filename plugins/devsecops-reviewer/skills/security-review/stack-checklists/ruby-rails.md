# Ruby / Rails checklist

## Injection and XSS
- `where("name = '#{params[:q]}'")`, `order(params[:sort])`, `find_by_sql`, `pluck`/`select` with interpolation, `exists?(params[:x])` (hash/array injection) → SQLi. Safe: `where(name: q)`, `where("name = ?", q)`, allowlisted sort columns.
- `system("... #{x}")`, backticks, `%x()`, `Open3` with a single string, `Kernel#open("|cmd")`, `IO.popen(string)` → command injection.
- `raw`, `html_safe`, `<%== %>`, `render inline: params[:x]`, `content_tag` with unescaped strings → XSS / template injection.
- `send_file(params[:path])`, `File.read(Rails.root.join(params[:f]))`, `render file:` with input → path traversal.
- `Marshal.load`, `YAML.load` (Psych < 4 / `unsafe_load`), `Oj.load` in object mode on untrusted data → deserialization RCE.
- `redirect_to params[:url]` (Rails 7 `allow_other_host` default protects only when enabled) → open redirect. `Net::HTTP.get(URI(params[:url]))` → SSRF.
- `constantize`/`safe_constantize`/`send`/`public_send` with user input → code execution or method abuse.
- Nokogiri with `NOENT`/`DTDLOAD` options → XXE.

## Auth and access control
- Controllers missing `before_action :authenticate_user!` or authorization (`authorize`, Pundit/CanCanCan `load_and_authorize_resource`); `skip_before_action` on sensitive actions.
- `Model.find(params[:id])` instead of `current_user.models.find(params[:id])` → IDOR.
- `params.permit!`, permitting `:role`, `:admin`, `:user_id` → mass assignment.
- `protect_from_forgery` disabled/`with: :null_session` on cookie-authenticated controllers.
- `has_secure_password` missing; custom `Digest::MD5`/`SHA1` password hashing.

## Config
- `config.consider_all_requests_local = true` in production; `secret_key_base` or credentials master key committed; `config.force_ssl = false`.
- `Rack::Cors` `origins '*'` with `credentials: true`; cookies without `secure`/`httponly`/`same_site`.
- `filter_parameters` missing `:password`, `:token` → secrets in logs.
