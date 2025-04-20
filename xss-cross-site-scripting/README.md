# XSS

| Endpoint | Protection Method | Description |
|----------|-------------------|-------------|
| `/vulnerable` | None | Intentionally vulnerable to demonstrate reflected XSS |
| `/escape-html` | HTML Encoding | Uses Python's `html.escape()` to neutralize HTML tags |
| `/csp-protected` | Content Security Policy | Implements strict CSP headers to prevent script execution |
| `/sanitize-input` | Input Sanitization | Uses Bleach library to clean malicious input |
| `/whitelist` | Whitelist Validation | Only allows alphanumeric and basic punctuation |
| `/no-js` | Plain Text Rendering | Treats all input as plain text without HTML rendering |
| `/jinja-autoescape` | Template Autoescaping | Demonstrates Jinja2's built-in autoescaping |
| `/httponly-cookie` | Secure Cookies | Sets HttpOnly and Secure flags on cookies |
| `/dom-protected` | Safe DOM Manipulation | Shows proper frontend handling with textContent |

## Test

```html
<h1>aaaa</h1>
<script>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">
<svg onload="alert('XSS')"></svg>
<a href="javascript:alert('XSS')">Click me</a>
'"><img src=x onerror=alert(1)>
```