# Static Files Setup

JavaScript and CSS can now be served as static files from `/_admin/static/` without requiring a build step.

## Directory Structure

```
internal/server/admin/admin_ui/static/
├── js/
│   └── utils.js          # Shared JavaScript utilities
└── css/
    └── common.css        # Shared CSS components
```

Files are embedded in the binary via `go:embed` and served with 30-day cache headers.

## Using Shared Utilities

### JavaScript (`utils.js`)

Load in templates via:
```html
<script src="/_admin/static/js/utils.js"></script>
```

Available functions:

- **`esc(s)`** — HTML escape a string (prevents XSS)
  ```js
  const safeHTML = esc(userInput);
  ```

- **`setupCopyButton(btn, source)`** — Attach copy-to-clipboard to a button
  ```js
  setupCopyButton(
    document.querySelector(".my-copy-btn"),
    "[data-snippet]"  // or DOM node
  );
  ```

- **`setupTabs(tabs, panes, attrTab, attrPane)`** — Generic tab switcher
  ```js
  // HTML: <button data-tab="foo">Foo</button>
  //       <div data-pane="foo">content</div>
  setupTabs("[data-tab]", "[data-pane]");
  ```

- **`fetchAndRender(url, container, fn, options)`** — Fetch JSON + render
  ```js
  fetchAndRender("/_api/services", hostEl, (data, el) => {
    el.innerHTML = data.services.map(s => `<div>${esc(s.name)}</div>`).join("");
  });
  ```

### CSS (`common.css`)

Already loaded in `layout.tmpl.html`. Provides:

- **Tab component** — `.tabs`, `.tab`, `.tab.active`, `.tab-pane`, `.tab-pane.active`
- **Copy button** — `.copy-btn` (overlay positioned)
- **Utility** — `.sr-only` (screenreader-only)

Generic `.tab` / `.tab-pane` classes replace per-page duplicates like `.harness-tab` / `.harness-pane`.

## Extracting More Code

### Pattern 1: Shared Utility Function

1. Find duplicate functions across pages (e.g., `esc()`, `escapeHTML()`)
2. Add to `static/js/utils.js`
3. Remove from templates
4. Templates now use the shared function

### Pattern 2: Shared CSS Pattern

1. Identify repeated CSS (e.g., `.harness-tab` looks like `.svc-tab`)
2. Add generic rules to `static/css/common.css` (e.g., `.tab`)
3. Update templates to use the generic class
4. Per-page overrides stay in `page-style` blocks

### Pattern 3: Standalone JS Module

For larger scripts:

1. Create `static/js/<name>.js`
2. Extract functions to the module, expose via `window.<Name> = {...}`
3. Load via `<script src="/_admin/static/js/<name>.js"></script>`
4. Call from `page-script` block

### Example: Extract copy-button handler

**Before** (inline in a page template):
```js
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-copy-target]");
  if (!btn) return;
  const target = document.querySelector(`[data-snippet="${btn.dataset.copyTarget}"]`);
  if (!target) return;
  try {
    await navigator.clipboard.writeText(target.textContent);
    // ... feedback animation ...
  } catch (_) {}
});
```

**After** (in utils.js, already done):
```js
function setupCopyButton(btn, source) { /* ... */ }
```

**In template**:
```html
<button class="copy-btn" data-copy-target="foo">Copy</button>
<script>
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy-target]");
    if (btn) setupCopyButton(btn, `[data-snippet="${btn.dataset.copyTarget}"]`);
  });
</script>
```

## No Build Step Required

Static files are served directly from the embedded FS with appropriate cache headers. To modify:

1. Edit `static/js/*.js` or `static/css/*.css`
2. Recompile (`make build` or `go build ./cmd/bouncer`)
3. Static files are re-embedded and restart will serve new versions

## Future: Unbundling

If static files grow or change frequently, you can:

1. Move `admin_ui/static/` out of the codebase (e.g., to a `web/` directory)
2. Serve via a separate HTTP server or CDN
3. Update template URLs from `/_admin/static/` to `https://cdn.example.com/static/`

The current embedded approach is zero-ops; future changes can be made without modifying the server.
