# Node.js / Express (also Koa, Fastify, NestJS, Next.js API routes) checklist

## Injection and XSS
- `db.query("... " + req.query.x)`, template literals in SQL, `sequelize.query(string)` without `replacements`/`bind`, knex `.raw(string)` → SQLi. Safe: placeholders `?`/`$1` with params, query builders.
- Mongo/Mongoose filters taken straight from `req.body`/`req.query` (`{ username: req.body.username }` where the value can be `{ "$ne": null }`), `$where`, `mapReduce` → NoSQL injection. Safe: cast to string, `express-mongo-sanitize`, schema validation.
- `child_process.exec/execSync(`... ${x}`)`, `spawn(cmd, { shell: true })` → command injection. Safe: `execFile/spawn` with an argument array and no shell.
- `res.send("<h1>" + req.query.name)`, EJS `<%- x %>`, Handlebars `{{{x}}}`, Pug `!{x}` → XSS. `res.json` is safe.
- `ejs.render(userTemplate)`, `new Function(x)`, `eval(x)`, `vm.runInNewContext(x)` (not a sandbox) → code/template injection.
- `res.sendFile(path.join(dir, req.params.f))`, `fs.readFile(base + name)` → path traversal. Safe: `sendFile(name, { root: dir })` plus rejecting `..`, or `path.resolve` + prefix check.
- `axios/fetch/got/request(req.body.url)` → SSRF. Check host allowlists and private IP blocking after DNS resolution.
- `res.redirect(req.query.next)` → open redirect.
- `node-serialize.unserialize`, `serialize-javascript` round-trips, `js-yaml.load` (v3 unsafe types), `libxmljs.parseXml(x, { noent: true })` → deserialization/XXE.
- Prototype pollution: `_.merge`/`Object.assign`/recursive merge of `req.body` into objects, `obj[req.body.key] = value`.
- Uploads (`multer`): no `fileFilter`/limits, `originalname` used as the stored path, stored under `public/`.

## Auth and access control
- Routes registered without the auth middleware used by sibling routes (`router.get('/admin/...', handler)` vs `router.use(requireAuth)` order).
- Role checks on `req.body.role`, `req.query.admin`, or a decoded-but-unverified JWT.
- `findById(req.params.id)` without an owner condition → IDOR.
- `jwt.decode()` used instead of `jwt.verify()`; `verify` without `algorithms`; hardcoded/short secret; long or missing `expiresIn`.
- `express-session` with a hardcoded `secret`, `cookie: { secure: false, httpOnly: false }`, no `sameSite`.
- Passwords with `crypto.createHash('md5'|'sha1'|'sha256')`. Safe: `bcrypt`, `argon2`, `scrypt` with salt.
- Login/reset endpoints without `express-rate-limit` or equivalent.
- `body-parser`/`express.json()` without size limits (low).

## Config
- `cors({ origin: '*', credentials: true })`, or `origin: true`/reflecting `req.headers.origin` with credentials.
- No `helmet()` (or equivalent headers) on apps that serve HTML; `app.disable('x-powered-by')` missing (info).
- Error handlers returning `err.stack` to clients; `NODE_ENV` defaulting to development.
- `process.env.X || 'hardcoded-secret'` fallbacks → hardcoded secret in practice.
- `console.log(req.body)` / logging tokens or passwords.
