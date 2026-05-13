package admin

import "github.com/go-chi/chi/v5"

// SettingsUIPath is the operator-facing settings page. Phase 1 is a
// thin shell — workspace info + sign-out — that will pick up real
// configuration (data-dir layout, version, MITM CA management, plan
// info) in later changes. Mounted here rather than in admin.go so a
// future settings JSON API has a natural home in this file.
const SettingsUIPath = "/_admin/settings"

// MountSettings wires the GET /_admin/settings UI shell. No JSON
// endpoints yet; admin gating is uniform via InternalPolicyMiddleware
// against the `ui_settings` action.
func MountSettings(r chi.Router) {
	mountUIPage(r, SettingsUIPath, "settings")
}
