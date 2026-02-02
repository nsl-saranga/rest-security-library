# restsecurity

A small, focused library to help keep your REST APIs safer. It gives you **validation**, **sanitization**, and **size limits** so you can spend less time worrying about bad input and more time building your app.

---

## Why this exists

Every API takes input from the outside world. That input can be malformed, too big, or crafted to break your app—SQL injection, path traversal, header injection, and so on. Handling all of that by hand is easy to get wrong and tedious to maintain.

**restsecurity** centralizes the boring, critical work: checking that requests match the shape you expect, cleaning strings before you use them, and capping payload size. Use it as Express middleware or call the helpers directly when you need more control.

---

## Install

```bash
npm install restsecurity
```

restsecurity is **TypeScript-first** and ships compiled JavaScript plus type declarations.

- **Runtime deps** (installed automatically): `express`, `body-parser`, `ajv`, `ajv-formats`
- **Dev deps** (if you are writing TS): `typescript`, `@types/express`, `@types/body-parser`

If you clone this repo and want to build it yourself:

```bash
npm install
npm run build   # runs tsc, emits dist/index.js + dist/index.d.ts
```

You can then import it from your own project (TS or JS) in the same way:

```typescript
import { validateRequest, sizeLimiter, sanitizeRequest } from "restsecurity";
```

---

## Quick start

Typical flow: limit body size → sanitize input → validate shape → run your handler.

```typescript
import express from "express";
import { validateRequest, sizeLimiter, sanitizeRequest } from "restsecurity";

const app = express();

// 1. Cap JSON body size (e.g. 1mb)
app.use(sizeLimiter("1mb"));

// 2. Sanitize body, query, and params (trim, escape HTML, strip dangerous patterns)
app.use(sanitizeRequest());

// 3. Validate request parts with JSON Schema
app.post(
  "/order",
  validateRequest({ body: orderSchema }),
  (req, res) => {
    res.json({ success: true, data: req.body });
  }
);

app.listen(3000);
```

You can use `validateRequest` and `sanitizeRequest` only on the routes that need them instead of globally.

---

## Validation

**validateRequest** ensures `body`, `query`, and/or `params` match a JSON Schema. If something doesn’t match, it responds with `400` and a list of errors; otherwise it calls `next()`.

```typescript
import { validateRequest } from "restsecurity";

const bodySchema = {
  type: "object",
  required: ["email", "name"],
  properties: {
    email: { type: "string", format: "email" },
    name: { type: "string", minLength: 1, maxLength: 100 }
  },
  additionalProperties: false
};

app.post("/users", validateRequest({ body: bodySchema }), (req, res) => {
  // req.body is guaranteed to match bodySchema
});
```

You can validate any combination of `body`, `query`, and `params` by passing the right keys and schemas. Validation uses **Ajv** with **ajv-formats** (e.g. `format: "email"`), so you can use normal JSON Schema plus formats.

Error responses look like:

```json
{
  "error": "Invalid request",
  "location": "body",
  "details": [
    { "field": "/email", "message": "must match format \"email\"" },
    { "field": "/name", "message": "must have required property 'name'" }
  ]
}
```

---

## Sanitization

Sanitization cleans strings so they’re safer to use in HTML, SQL, file paths, headers, or shell commands. You can use the **middleware** to sanitize all incoming body/query/params, or use the **low-level helpers** when you need to clean a single value.

### Using the middleware

**sanitizeRequest(options)** runs over `req.body`, `req.query`, and `req.params` and sanitizes every string value (recursively). By default it:

- trims whitespace  
- removes dangerous patterns (e.g. `<script>`, `onclick=...`)  
- escapes HTML (`<`, `>`, `&`, quotes, etc.)

So by default you get basic XSS and script-injection mitigation. You can then turn on extra defenses when you know input might be used in SQL, file paths, headers, or shell.

```typescript
import { sanitizeRequest } from "restsecurity";

// Default: trim, remove dangerous patterns, escape HTML
app.use(sanitizeRequest());

// Stricter: also remove path traversal, CRLF, and escape for SQL/shell when needed
app.use(
  sanitizeRequest({
    blockPathTraversal: true,  // strip "../" and encoded variants
    removeCrlf: true,         // strip \r\n (header/CRLF injection)
    escapeSql: true,          // escape DB special characters (defense in depth)
    escapeShell: true         // escape shell metacharacters
  })
);
```

Options you can pass:

| Option | Default | What it does |
|--------|--------|----------------|
| `trim` | `true` | Trim leading/trailing whitespace |
| `escape` | `true` | Escape HTML (`<`, `>`, `&`, quotes, etc.) |
| `stripTags` | `false` | Remove HTML tags (e.g. `<b>`) |
| `removeDangerous` | `true` | Remove `<script>` and event handlers |
| `blockPathTraversal` | `false` | Remove `../`, `..\`, and encoded path traversal |
| `removeCrlf` | `false` | Remove `\r\n` / `\n` (CRLF / header injection) |
| `escapeSql` | `false` | Escape DB special characters (SQL injection mitigation) |
| `escapeShell` | `false` | Escape shell metacharacters (command injection mitigation) |

Use `escapeSql` and `escapeShell` as **extra** layers; the main defenses are still parameterized queries and avoiding passing user input straight into the shell.

### Using the helpers yourself

When you’re building a SQL string, a file path, or a shell command, you can sanitize that one value:

```typescript
import {
  escapeHtml,
  escapeSql,
  blockPathTraversal,
  removeCrlf,
  escapeShell,
  sanitizeValue,
  sanitizeObject
} from "restsecurity";

// Single string
escapeHtml("<script>alert(1)</script>");
// "&lt;script&gt;alert(1)&lt;/script&gt;"

escapeSql("O'Brien");
// "O\\'Brien"

blockPathTraversal("../../../etc/passwd");
// "etc/passwd"

removeCrlf("value\r\nX-Injected: evil");
// "valueX-Injected: evil"

escapeShell("file; rm -rf /");
// "file\\; rm -rf /"

// One value with options
sanitizeValue(userInput, { escape: true, blockPathTraversal: true });

// Whole object (e.g. req.body) with the same options as the middleware
sanitizeObject(req.body, { removeCrlf: true, escapeSql: true });
```

So: **middleware** = “sanitize everything on the request”; **helpers** = “sanitize this one thing before I use it.”

---

## What each sanitizer is for

- **escapeHtml** – Use before putting a string into HTML (e.g. templates). Escapes `&`, `<`, `>`, `"`, `'`, `/`.
- **escapeSql** – Escapes characters that are special in SQL string literals (quote, backslash, null, newlines). Use **with** parameterized queries as defense in depth, not instead of them.
- **blockPathTraversal** – Removes `../`, `..\`, and common encoded forms. Use for any user-controlled path or filename.
- **removeCrlf** – Strips `\r\n` and `\n`. Use when the value might end up in HTTP headers or somewhere line breaks could change meaning.
- **escapeShell** – Escapes characters that have meaning in shells (`;`, `|`, `&`, `$`, backticks, etc.). Use when passing user input into a shell command; prefer APIs that don’t use the shell when you can.

---

## Size limiting

**sizeLimiter(limit)** returns Express middleware that parses JSON bodies and enforces a maximum size. Default is `"1mb"`. This helps avoid huge payloads tying up memory or causing DoS.

```typescript
import { sizeLimiter } from "restsecurity";

app.use(sizeLimiter("1mb"));
// or
app.post("/upload-metadata", sizeLimiter("256kb"), handler);
```

The limit uses the same format as body-parser (e.g. `"1mb"`, `"256kb"`).

---

## Order of operations

A good order is:

1. **sizeLimiter** – Reject oversized bodies before you do any real work.
2. **sanitizeRequest** – Clean strings so later code and validation see safe data.
3. **validateRequest** – Enforce structure and types with JSON Schema.
4. Your route handler – Use `req.body` / `req.query` / `req.params` with confidence.

So: size → sanitize → validate → business logic.

---

## API summary

| Export | Description |
|--------|-------------|
| `validateRequest({ body?, query?, params? })` | Middleware: validate request parts with JSON Schema; 400 on failure. |
| `sizeLimiter(limit?)` | Middleware: parse JSON body and enforce size (default `"1mb"`). |
| `sanitizeRequest(options?)` | Middleware: sanitize `req.body`, `req.query`, `req.params`. |
| `sanitizeValue(value, options?)` | Sanitize a single value (string or pass-through). |
| `sanitizeObject(data, options?)` | Recursively sanitize an object/array. |
| `escapeHtml(str)` | Escape HTML special characters. |
| `escapeSql(str)` | Escape DB special characters. |
| `blockPathTraversal(str)` | Remove path traversal sequences. |
| `removeCrlf(str)` | Remove `\r\n` / `\n`. |
| `escapeShell(str)` | Escape shell metacharacters. |
| `stripHtmlTags(str)` | Remove HTML tags. |
| `removeDangerousPatterns(str)` | Remove script tags and event handlers. |
| `trim(str)` | Trim whitespace. |

---

## License

ISC.
