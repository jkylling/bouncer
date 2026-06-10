# Static assets

Shared JS/CSS for the `/_admin` dashboard, embedded via `go:embed`
and served from `/_admin/static/` (see `admin.serveStaticHandler`).
No build step — edit, rebuild the binary, done.

- `js/utils.js` — shared helpers (`esc`, fetch wrappers, toasts).
  Load with `<script src="/_admin/static/js/utils.js"></script>`.
- `css/admin-ui.css` — shared dashboard styles.

Templates live one level up in `admin_ui/`; per-page snippets in
`partials/`.
