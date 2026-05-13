package connections

// ProviderInfo reports which connect modes are live for one provider.
// Drives the wizard's two-tab panel: PasteAvailable is always true;
// OAuthAvailable lights up when the operator started bouncer with
// `BOUNCER_<PROVIDER>_CLIENT_ID` + `BOUNCER_<PROVIDER>_CLIENT_SECRET`
// in the environment, so a future browser-mediated OAuth flow has
// somewhere to dial.
type ProviderInfo struct {
	PasteAvailable bool `json:"paste_available"`
	OAuthAvailable bool `json:"oauth_available"`
}

// ProviderAvailability returns the per-provider info derived from
// env. Caller passes the env map (`map[string]string{}`) so tests can
// stub a deterministic environment without touching os.Setenv.
//
// We accept the full env map rather than reading os.Getenv inline so
// the HTTP layer can resolve the values once at boot and pass a frozen
// snapshot, instead of having every request shell out to the OS.
func ProviderAvailability(env map[string]string) map[string]ProviderInfo {
	out := make(map[string]ProviderInfo, len(SupportedProviders))
	for _, p := range SupportedProviders {
		envPrefix := "BOUNCER_" + envName(p) + "_"
		out[p] = ProviderInfo{
			PasteAvailable: true,
			OAuthAvailable: env[envPrefix+"CLIENT_ID"] != "" && env[envPrefix+"CLIENT_SECRET"] != "",
		}
	}
	return out
}

// envName upper-cases a provider name into its env-var component.
// "google" -> "GOOGLE", "slack.api" -> "SLACK".
func envName(p string) string {
	b := make([]byte, len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
