# Frontend / SPA checklist (React, Vue, Angular, Svelte, plain DOM)

## DOM XSS
- Sources: `location.hash/search/href`, `document.referrer`, `window.name`, `postMessage` data, URL params via router, `localStorage` written from untrusted data, API fields containing user content.
- Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery `.html()/.append(html)/$(userString)`, `eval`, `setTimeout(string)`, `new Function`, `element.setAttribute('on…')`, `a.href = userUrl` / `window.location = userUrl` (`javascript:` URLs), `iframe.srcdoc`.
- React: `dangerouslySetInnerHTML={{ __html: x }}` without a sanitizer (DOMPurify); `href={userUrl}` without scheme check. Vue: `v-html`. Angular: `bypassSecurityTrustHtml/Url/Script`, `[innerHTML]` with sanitizer bypass. Svelte: `{@html x}`.
- `postMessage` listeners without `event.origin` checks; `postMessage(data, '*')` with sensitive data.

## Client-side trust (report as logic findings with the server code they rely on)
- Prices, totals, discounts, roles or permission flags computed in the browser and sent to the server.
- Authorization done only by hiding UI (routes/guards) with no server check.
- Validation only in the form, none on the API.

## Secrets and config in the bundle
- API keys, private tokens, or service credentials in frontend code or `.env` files exposed via `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_` prefixes (publishable keys are fine; secret keys are not).
- Tokens stored in `localStorage` (prefer httpOnly cookies) when XSS risk exists (low/medium).
- Source maps with secrets; debug flags enabled in production builds.
