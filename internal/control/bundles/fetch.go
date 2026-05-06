package bundles

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jkylling/bouncer/internal/httpdo"
)

// Caps so a malicious or accidentally-huge tarball can't fill the
// operator's disk: 64 MiB total, 16 MiB per entry.
const (
	maxBundleBytes int64 = 64 << 20
	maxFileBytes   int64 = 16 << 20
)

// Env hooks let the e2e suite redirect network calls to a local
// httptest-style server. Production leaves them unset.
const (
	envAPIBase      = "BOUNCER_GITHUB_API_BASE"
	envCodeloadBase = "BOUNCER_GITHUB_CODELOAD_BASE"
)

// Fetcher resolves Git refs to commit SHAs and downloads bundles.
// Construct with NewFetcher; fields are private so all defaulting
// happens at construction.
type Fetcher struct {
	httpClient   httpdo.Client
	token        string
	apiBase      string
	codeloadBase string
}

// FetcherOpts configures NewFetcher. Zero values fall back to
// production defaults (env-overridable for the GitHub endpoints).
type FetcherOpts struct {
	Token        string
	HTTPClient   httpdo.Client
	APIBase      string
	CodeloadBase string
}

func NewFetcher(opts FetcherOpts) *Fetcher {
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	if opts.APIBase == "" {
		opts.APIBase = envOrDefault(envAPIBase, "https://api.github.com")
	}
	if opts.CodeloadBase == "" {
		opts.CodeloadBase = envOrDefault(envCodeloadBase, "https://codeload.github.com")
	}
	return &Fetcher{
		httpClient:   opts.HTTPClient,
		token:        opts.Token,
		apiBase:      strings.TrimRight(opts.APIBase, "/"),
		codeloadBase: strings.TrimRight(opts.CodeloadBase, "/"),
	}
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// ResolveSHA returns the 40-char commit SHA the ref points at. Full
// SHAs short-circuit; tag/branch refs hit GitHub's commits API.
func (f *Fetcher) ResolveSHA(ctx context.Context, ref Ref) (string, error) {
	if ref.Version == "" {
		return "", fmt.Errorf("ref %s: version is required to resolve", ref)
	}
	if IsFullSHA(ref.Version) {
		return strings.ToLower(ref.Version), nil
	}
	endpoint := fmt.Sprintf("%s/repos/%s/%s/commits/%s",
		f.apiBase, url.PathEscape(ref.Owner), url.PathEscape(ref.Repo), url.PathEscape(ref.Version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	// vnd.github.sha returns the SHA as the body — no JSON parse.
	req.Header.Set("Accept", "application/vnd.github.sha")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		var apiErr struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &apiErr)
		if apiErr.Message != "" {
			return "", fmt.Errorf("resolve %s: github %s: %s", ref, resp.Status, apiErr.Message)
		}
		return "", fmt.Errorf("resolve %s: github %s", ref, resp.Status)
	}
	sha := strings.TrimSpace(string(body))
	if !IsFullSHA(sha) {
		return "", fmt.Errorf("resolve %s: github returned %q which is not a SHA", ref, sha)
	}
	return strings.ToLower(sha), nil
}

// Download fetches the codeload tarball for a fully-resolved SHA.
// Caller closes the body. Used by Install via Stage; kept exported
// for `apis fetch` (air-gap workflow).
func (f *Fetcher) Download(ctx context.Context, ref Ref, sha string) (io.ReadCloser, error) {
	if !IsFullSHA(sha) {
		return nil, fmt.Errorf("download %s: sha %q is not a full 40-char SHA", ref, sha)
	}
	endpoint := fmt.Sprintf("%s/%s/%s/tar.gz/%s",
		f.codeloadBase, url.PathEscape(ref.Owner), url.PathEscape(ref.Repo), sha)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", ref, err)
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("download %s: github %s: %s", ref, resp.Status, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

// ExtractTarGz reads a gzipped tar from r and writes it under
// destDir. The codeload tarball wraps everything in `<repo>-<sha>/`;
// that prefix is stripped. Caps are enforced and absolute / escaping
// paths and symlinks are rejected.
func ExtractTarGz(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxBundleBytes+1))
	cleanDest := filepath.Clean(destDir)
	var written int64
	var prefix string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		// Skip pax metadata: TypeXGlobalHeader surfaces as a discrete
		// entry in some codeload archives — without this guard the
		// prefix capture latches onto `pax_global_header`.
		if hdr.Typeflag == tar.TypeXGlobalHeader || hdr.Typeflag == tar.TypeXHeader {
			continue
		}
		clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(hdr.Name)), "./")
		if prefix == "" {
			if i := strings.IndexByte(clean, '/'); i >= 0 {
				prefix = clean[:i]
			} else {
				prefix = clean
			}
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(clean, prefix), "/")
		if rel == "" {
			continue
		}
		if rel == ".." || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") || strings.HasPrefix(rel, "/") {
			return fmt.Errorf("tar entry %q escapes destination", hdr.Name)
		}
		target := filepath.Join(destDir, filepath.FromSlash(rel))
		// Belt and braces: confirm the resolved target stays under
		// destDir even if a platform path quirk slips past the
		// lexical check.
		if cleaned := filepath.Clean(target); cleaned != cleanDest &&
			!strings.HasPrefix(cleaned, cleanDest+string(filepath.Separator)) {
			return fmt.Errorf("tar entry %q escapes destination", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > maxFileBytes {
				return fmt.Errorf("tar entry %s exceeds %d-byte file cap", rel, maxFileBytes)
			}
			n, err := writeRegular(target, tr)
			if err != nil {
				return err
			}
			written += n
			if written > maxBundleBytes {
				return fmt.Errorf("tarball exceeds %d-byte bundle cap", maxBundleBytes)
			}
		default:
			// Skip symlinks, devices, etc. Bundles are pure YAML.
			continue
		}
	}
	return nil
}

func writeRegular(target string, tr io.Reader) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(tr, maxFileBytes+1))
	closeErr := f.Close()
	if err != nil {
		return n, err
	}
	if closeErr != nil {
		return n, closeErr
	}
	if n > maxFileBytes {
		return n, fmt.Errorf("tar entry %s exceeds %d-byte file cap", target, maxFileBytes)
	}
	return n, nil
}

// Install resolves ref to a SHA, downloads the tarball, and lays the
// bundle out under <apisDir>/<bundle-name>/ with a generated
// source.yaml. Extraction goes via a sibling `.tmp.<rand>/` and is
// renamed in at the end so a killed install can't leave a partial
// bundle on disk.
func (f *Fetcher) Install(ctx context.Context, apisDir string, ref Ref, renames map[string]string) (string, error) {
	if ref.Version == "" {
		return "", fmt.Errorf("install %s: version is required (pass `<host>/<owner>/<repo>@<ref>`)", ref)
	}
	if err := os.MkdirAll(apisDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir apis dir: %w", err)
	}
	tmpDir, err := os.MkdirTemp(apisDir, ".tmp.*")
	if err != nil {
		return "", fmt.Errorf("mkdtemp: %w", err)
	}
	cleanup := tmpDir
	defer func() {
		if cleanup != "" {
			_ = os.RemoveAll(cleanup)
		}
	}()

	if _, err := f.Stage(ctx, ref, tmpDir, renames); err != nil {
		return "", err
	}
	manifest, err := LoadManifest(filepath.Join(tmpDir, ManifestFile))
	if err != nil {
		return "", fmt.Errorf("install %s: %w", ref, err)
	}
	finalDir := BundleDir(apisDir, manifest.Name)
	if _, err := os.Stat(finalDir); err == nil {
		return "", fmt.Errorf("install %s: %s already exists; remove or upgrade first", ref, finalDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return "", fmt.Errorf("rename %s -> %s: %w", tmpDir, finalDir, err)
	}
	cleanup = ""
	return finalDir, nil
}

// Stage resolves ref, downloads, extracts into stageDir, validates
// the manifest, and writes source.yaml. Returns the resolved SHA.
// Caller owns stageDir — Install renames it; `apis fetch` repacks it.
func (f *Fetcher) Stage(ctx context.Context, ref Ref, stageDir string, renames map[string]string) (string, error) {
	if ref.Version == "" {
		return "", fmt.Errorf("stage %s: version is required (pass `<host>/<owner>/<repo>@<ref>`)", ref)
	}
	sha, err := f.ResolveSHA(ctx, ref)
	if err != nil {
		return "", err
	}
	body, err := f.Download(ctx, ref, sha)
	if err != nil {
		return "", err
	}
	defer body.Close()
	if err := ExtractTarGz(body, stageDir); err != nil {
		return "", err
	}
	if _, err := LoadManifest(filepath.Join(stageDir, ManifestFile)); err != nil {
		return "", fmt.Errorf("stage %s: %w", ref, err)
	}
	src := &SourceRecord{
		Ref:         ref.String(),
		ResolvedSHA: sha,
		FetchedAt:   time.Now().UTC().Truncate(time.Second),
		APIRenames:  renames,
	}
	if err := WriteSource(filepath.Join(stageDir, SourceFile), src); err != nil {
		return "", err
	}
	return sha, nil
}
