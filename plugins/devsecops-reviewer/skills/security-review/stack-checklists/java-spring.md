# Java / Kotlin / Spring checklist

## Injection and XSS
- `Statement.executeQuery("..." + x)`, `jdbcTemplate.query("..." + x)`, `entityManager.createQuery("... " + x)` (JPQL/HQL), `@Query` with SpEL concatenation, `Criteria` with string fragments → SQLi. Safe: `PreparedStatement` with `?`, named parameters, Spring Data derived queries.
- Mongo `new BasicQuery(json)` / `$where` with input → NoSQL injection.
- `Runtime.getRuntime().exec(String)` / `ProcessBuilder("sh", "-c", x)` → command injection. Safe: `ProcessBuilder(List.of("cmd", arg))` with validated args.
- Thymeleaf `th:utext`, JSP `<%= x %>` / `${x}` without `<c:out>`/`fn:escapeXml`, returning `String` HTML from `@RestController` with `text/html` → XSS.
- SpEL `parser.parseExpression(userInput)`, Thymeleaf template names from input (`return "views/" + lang;` → view-name SSTI), Velocity/Freemarker templates built from input → template/expression injection.
- `new File(base, request.getParameter("f"))`, `Paths.get(base, name)` without `normalize()` + `startsWith(base)` → path traversal. Also `ZipEntry` names (Zip Slip).
- `new URL(userUrl).openStream()`, `RestTemplate.getForObject(userUrl)`, `WebClient` with user hosts → SSRF.
- `"redirect:" + request.getParameter("next")` → open redirect.
- `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory` without disabling DTDs/external entities (`disallow-doctype-decl`) → XXE.
- `ObjectInputStream.readObject` on untrusted bytes, `XMLDecoder`, XStream without allowlist, Jackson `enableDefaultTyping`/`@JsonTypeInfo(use = CLASS)`, SnakeYAML `new Yaml().load` (pre-2.0 constructor) → deserialization RCE.
- JNDI lookups with user input; Log4j 2 < 2.17.1 (check dependencies).
- `MultipartFile.getOriginalFilename()` used as a path; no type/size validation.
- LDAP: `ctx.search(base, "(uid=" + user + ")", ...)` → LDAP injection; use filter arguments `{0}`.

## Auth and access control
- `SecurityFilterChain` with `.permitAll()` on sensitive paths, `anyRequest().permitAll()`, matcher order mistakes, `web.ignoring()` on API paths.
- Missing `@PreAuthorize`/`@Secured`/`@RolesAllowed` on new admin endpoints (and `@EnableMethodSecurity` actually enabled).
- `repository.findById(id)` without checking `principal` ownership → IDOR.
- `@RequestBody` binding entities directly (`User` with `role`/`admin` fields) → mass assignment; use DTOs.
- `csrf().disable()` with cookie/session auth.
- JWT: `parseUnsecuredClaims`, missing signature verification, `alg: none` accepted, hardcoded signing key; no expiration.
- `NoOpPasswordEncoder`, `MessageDigest.getInstance("MD5"|"SHA-1")` for passwords. Safe: `BCryptPasswordEncoder`, `Argon2PasswordEncoder`.

## Config
- `application.properties/yml`: `management.endpoints.web.exposure.include=*` (Actuator: env, heapdump), `server.error.include-stacktrace=always`, `spring.h2.console.enabled=true`, `debug=true`, literal `spring.datasource.password`.
- `@CrossOrigin(origins = "*", allowCredentials = "true")`, `allowedOriginPatterns("*")` with credentials.
- Cookies without `Secure`/`HttpOnly`/`SameSite`; `server.servlet.session.cookie.secure=false`.
- `new Random()` for tokens (use `SecureRandom`); `Cipher.getInstance("AES")` (= ECB) or `"DES"`; TrustManager accepting all certs; `HostnameVerifier` returning true.
- Logging `password`, tokens, or entire request bodies (`log.info("login {}", request)`).
