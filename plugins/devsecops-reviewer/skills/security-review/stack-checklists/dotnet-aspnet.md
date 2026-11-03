# C# / ASP.NET Core checklist

## Injection and XSS
- `FromSqlRaw($"... {x}")`, `ExecuteSqlRaw` with interpolation/concatenation, `SqlCommand("..." + x)` → SQLi. Safe: `FromSqlInterpolated`, parameters (`SqlParameter`), LINQ.
- `Process.Start("cmd.exe", "/c " + x)`, `ProcessStartInfo` with `UseShellExecute` and input → command injection.
- `@Html.Raw(x)`, `HtmlString(x)`, `MarkupString` (Blazor) on user data → XSS. Razor `@x` encodes by default.
- `Path.Combine(root, userName)` (an absolute second argument replaces the root!), `File.ReadAllText`, `PhysicalFile` without `Path.GetFullPath` + `StartsWith(root)` → path traversal.
- `HttpClient.GetAsync(userUrl)` → SSRF. `Redirect(returnUrl)` without `Url.IsLocalUrl` / `LocalRedirect` → open redirect.
- `XmlDocument` with `XmlResolver` set (or .NET Framework < 4.5.2 defaults), `XmlReaderSettings { DtdProcessing = Parse }` → XXE.
- `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, Json.NET `TypeNameHandling.All/Auto` on untrusted input → deserialization RCE.
- `DirectorySearcher.Filter = "(uid=" + user + ")"` → LDAP injection.
- `IFormFile.FileName` as the stored path; no extension/content checks; saved under `wwwroot`.

## Auth and access control
- Controllers/actions missing `[Authorize]` where siblings have it; `[AllowAnonymous]` on sensitive actions; minimal APIs without `.RequireAuthorization()`.
- Role checks against claims the client controls; missing `[Authorize(Roles = "Admin")]`/policies for admin endpoints.
- `_db.Orders.Find(id)` without filtering by `User.FindFirstValue(ClaimTypes.NameIdentifier)` → IDOR.
- Binding EF entities directly from the request (`[FromBody] User user`) → over-posting; use DTOs/`[Bind]`.
- `[IgnoreAntiforgeryToken]` / missing `[ValidateAntiForgeryToken]` on cookie-authenticated POSTs.
- JWT: `ValidateIssuerSigningKey = false`, `ValidateLifetime = false`, `RequireSignedTokens = false`, symmetric key literal in code.
- Custom password hashing with `MD5`/`SHA1`/`SHA256.Create()`; safe: `PasswordHasher<T>` / Identity.

## Config
- `app.UseDeveloperExceptionPage()` outside `if (env.IsDevelopment())`; `ASPNETCORE_ENVIRONMENT=Development` in deploy files.
- Connection strings with passwords in `appsettings.json` (should be user-secrets/Key Vault/env).
- `policy.AllowAnyOrigin().AllowCredentials()` (throws at runtime) or `SetIsOriginAllowed(_ => true).AllowCredentials()`.
- `CookieOptions { Secure = false, HttpOnly = false }`, `SameSiteMode.None` without need; no `UseHsts`/`UseHttpsRedirection`.
- `new Random()` for tokens (use `RandomNumberGenerator`); `ServerCertificateCustomValidationCallback = (...) => true`.
- `_logger.LogInformation("Login {User} {Password}", ...)`.
