package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jkylling/bouncer/internal/auth"
	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/connections"
	"github.com/jkylling/bouncer/internal/control/tokens"
)

// connectionTools returns the two service-agnostic tools the
// instruction fragment names. They depend only on the connection
// store; the per-service `get_{service}_token` tools are built
// separately from the bundle list.
func connectionTools() []tool {
	return []tool{
		{
			Name:        "connections",
			Title:       "List bouncer connections",
			Description: "Returns the per-service connections the tenant has authorized to bouncer. Each entry carries `provider`, `created_at`, and a redacted credential body (client_id only). The agent calls this before suggesting a /{service}-token prompt — only listed services can be staged.",
			InputSchema: schemaObject(nil, nil),
			Run:         runConnections,
		},
		{
			Name:        "credentials_staged",
			Title:       "Check whether a service is staged",
			Description: "Returns {staged:true|false} for a given service slug. The agent calls this to decide whether to invoke the /{service}-token prompt or proceed with the upstream call.",
			InputSchema: schemaObject(map[string]any{
				"service": map[string]any{"type": "string"},
			}, []string{"service"}),
			Run: runCredentialsStaged,
		},
	}
}

func runConnections(_ context.Context, deps Deps, _ json.RawMessage) (any, *Error) {
	if deps.ConnectionStore == nil {
		return map[string]any{"connections": []any{}}, nil
	}
	list, err := deps.ConnectionStore.List()
	if err != nil {
		return nil, internalError("list connections: " + err.Error())
	}
	if list == nil {
		list = []connections.Connection{}
	}
	return map[string]any{"connections": list}, nil
}

type credentialsStagedParams struct {
	Service string `json:"service"`
}

func runCredentialsStaged(_ context.Context, deps Deps, params json.RawMessage) (any, *Error) {
	var p credentialsStagedParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, invalidParams("could not decode params: %v", err)
	}
	if p.Service == "" {
		return nil, invalidParams(`"service" is required`)
	}
	if deps.ConnectionStore == nil {
		return map[string]any{"staged": false, "service": p.Service}, nil
	}
	_, err := deps.ConnectionStore.Get(p.Service)
	if errors.Is(err, connections.ErrNotFound) || errors.Is(err, connections.ErrUnknown) {
		return map[string]any{"staged": false, "service": p.Service}, nil
	}
	if err != nil {
		return nil, internalError("read connection: " + err.Error())
	}
	return map[string]any{"staged": true, "service": p.Service}, nil
}

// makeGetTokenTool builds a `get_{service}_token` tool for one
// bundle. The tool's response shape carries the same fields whether
// the bundle's manifest declared env vars + credential template or
// not, so the agent always sees a stable structure.
func makeGetTokenTool(b *bundles.BundleToken) tool {
	svc := b.Spec.Slug
	return tool{
		Name:        "get_" + svc + "_token",
		Title:       "Stage " + svc + " credentials",
		Description: "Returns a bouncer-issued bearer for " + svc + " plus the on-disk path, file template, and env-var map declared by the matching bundle. The agent writes the file and exports the env-vars before invoking the matching CLI through bouncer-wrap.",
		InputSchema: schemaObject(nil, nil),
		Run: func(_ context.Context, deps Deps, _ json.RawMessage) (any, *Error) {
			return runGetServiceToken(deps, b)
		},
	}
}

// GetServiceTokenResult is the response shape for get_<service>_token.
// Exported so callers and tests can decode without restating it.
type GetServiceTokenResult struct {
	Service        string            `json:"service"`
	AccessToken    string            `json:"access_token"`
	CredentialPath string            `json:"credential_path"`
	CredentialMode string            `json:"credential_mode"`
	FileTemplate   string            `json:"file_template"`
	Env            map[string]string `json:"env,omitempty"`
}

// byoAccessTokenTTLSeconds is the access-JWT lifetime for BYO-access-
// token variants. Matches the typical 1-hour upstream lifetime — once
// the pasted upstream token expires, the wrapping JWT is dead too, so
// a longer TTL would just stretch the eventual upstream 401.
const byoAccessTokenTTLSeconds int64 = 3600

func runGetServiceToken(deps Deps, b *bundles.BundleToken) (any, *Error) {
	svc := b.Spec.Slug
	if deps.ConnectionStore == nil {
		return nil, serviceNotConnectedError(svc)
	}
	conn, err := deps.ConnectionStore.Get(svc)
	if errors.Is(err, connections.ErrNotFound) || errors.Is(err, connections.ErrUnknown) {
		return nil, serviceNotConnectedError(svc)
	}
	if err != nil {
		return nil, internalError("read connection: " + err.Error())
	}
	if deps.Keys == nil {
		return nil, internalError("server keys not configured")
	}
	token, mintErr := mintServiceToken(deps.Keys, conn, svc)
	if errors.Is(mintErr, errNoCredentialStaged) {
		return nil, serviceNotConnectedError(svc)
	}
	if mintErr != nil {
		return nil, internalError("issue token: " + mintErr.Error())
	}
	return GetServiceTokenResult{
		Service:        svc,
		AccessToken:    token,
		CredentialPath: b.Spec.Credential.Path,
		CredentialMode: b.Spec.Credential.Mode,
		FileTemplate:   b.Spec.Credential.Template,
		Env:            b.Spec.Env,
	}, nil
}

// errNoCredentialStaged signals that the stored connection has neither
// a refresh-token triple nor a BYO access token to mint a JWT from.
// Callers turn this into the same service_not_connected response the
// missing-record path returns, so the agent's recovery flow is one
// branch instead of two.
var errNoCredentialStaged = errors.New("no credential staged")

// mintServiceToken picks the right tokens primitive for the stored
// connection shape. Refresh-token triples flow through IssueRefresh
// (the /token endpoint rotates them on demand); BYO access-token
// variants flow through Issue (the JWT just wraps the pasted bearer
// for its remaining lifetime).
func mintServiceToken(keys *auth.ServerKeys, conn connections.Connection, svc string) (string, error) {
	if conn.Credentials.RefreshToken != "" {
		// The JWT carries refresh_token + token_url; the agent pairs
		// it with client_id + client_secret when exchanging at the
		// proxy's /token endpoint. Per the wizard's design, the
		// client triple is the operator's to manage and bouncer
		// doesn't leak the secret to the agent — the agent only sees
		// the resulting bearer.
		res, err := tokens.IssueRefresh(context.Background(), keys, &tokens.RefreshSpec{
			Subject:      "bouncer-" + svc,
			RefreshToken: conn.Credentials.RefreshToken,
			TokenURL:     conn.Credentials.TokenURL,
		})
		if err != nil {
			return "", fmt.Errorf("refresh: %w", err)
		}
		return res.Token, nil
	}
	if at := conn.Fields["access_token"]; at != "" {
		res, err := tokens.Issue(context.Background(), keys, &tokens.Spec{
			Subject:     "bouncer-" + svc,
			AccessToken: at,
			TTLSeconds:  byoAccessTokenTTLSeconds,
		})
		if err != nil {
			return "", fmt.Errorf("access: %w", err)
		}
		return res.Token, nil
	}
	return "", errNoCredentialStaged
}

// serviceNotConnectedError mirrors the proxy's structured 401 body so
// the agent's auto-on-401 flow handles tool-level denials the same
// way it handles transport-level denials.
func serviceNotConnectedError(svc string) *Error {
	return &Error{
		Code:    codeInvalidRequest,
		Message: fmt.Sprintf("service_not_connected: %s", svc),
		Data: map[string]any{
			"error":   "service_not_connected",
			"service": svc,
			"message": "Connect " + svc + " to bouncer to use this tool.",
		},
	}
}
