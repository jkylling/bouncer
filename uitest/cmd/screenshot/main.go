package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/playwright-community/playwright-go"
)

// Mockup screens to capture. Each tuple: (slug, hashed screen on
// page, optional dashboard tab).
var mockupShots = []struct {
	name      string // file slug
	screen    string // calls show(screen)
	tab       string // optional .nav-item data-tab to activate
	clickInit string // optional pre-screen JS (e.g. for connect-service grid selection)
}{
	{name: "landing", screen: "landing"},
	{name: "dash-traffic", screen: "dashboard", tab: "traffic"},
	{name: "dash-policies", screen: "dashboard", tab: "policies"},
	{name: "dash-agents", screen: "dashboard", tab: "agents"},
	{name: "dash-connections", screen: "dashboard", tab: "connections"},
	{name: "dash-settings", screen: "dashboard", tab: "settings"},
}

// Live screens to capture. We just navigate to URL paths after login.
var liveShots = []struct {
	name string
	path string
}{
	{name: "services", path: "/_admin/services"},
	{name: "service-detail", path: "/_admin/services/google"},
	{name: "tokens", path: "/_admin/tokens"},
	{name: "policies", path: "/_admin/policies"},
	{name: "traffic", path: "/_admin/traffic"},
	{name: "settings", path: "/_admin/settings"},
}

var viewports = []struct {
	name string
	w, h int
}{
	{name: "wide", w: 1440, h: 900},
	{name: "narrow", w: 720, h: 900},
}

func main() {
	live := flag.String("live", "http://127.0.0.1:18080", "live bouncer base URL")
	mockup := flag.String("mockup", "", "mockup URL or file:// path; empty skips mockup")
	password := flag.String("password", "bouncer123", "admin password for live")
	outDir := flag.String("out", "/tmp/screens", "screenshot output directory")
	flag.Parse()
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	pw, err := playwright.Run()
	must(err)
	defer pw.Stop()
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true)})
	must(err)
	defer browser.Close()

	for _, vp := range viewports {
		ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: vp.w, Height: vp.h}})
		must(err)
		page, err := ctx.NewPage()
		must(err)

		// Live
		if *live != "" {
			loginLive(page, *live, *password)
			for _, s := range liveShots {
				url := *live + s.path
				_, _ = page.Goto(url, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle})
				path := filepath.Join(*outDir, fmt.Sprintf("live-%s-%s.png", s.name, vp.name))
				shot(page, path)
			}
		}

		// Mockup
		if *mockup != "" {
			if _, err := page.Goto(*mockup, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle}); err == nil {
				for _, m := range mockupShots {
					switchMockup(page, m.screen, m.tab)
					path := filepath.Join(*outDir, fmt.Sprintf("mockup-%s-%s.png", m.name, vp.name))
					shot(page, path)
				}
			} else {
				log.Printf("mockup goto failed: %v", err)
			}
		}
		_ = ctx.Close()
	}
	fmt.Println("wrote screenshots to", *outDir)
}

func loginLive(page playwright.Page, base, password string) {
	if _, err := page.Goto(base+"/_admin/login", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle}); err != nil {
		log.Fatalf("goto login: %v", err)
	}
	if err := page.Locator(`input[name="password"]`).Fill(password); err != nil {
		log.Fatalf("fill password: %v", err)
	}
	if _, err := page.ExpectResponse("**/_api/admin/login", func() error {
		return page.Locator(`form button[type="submit"]`).Click()
	}); err != nil {
		log.Fatalf("submit login: %v", err)
	}
	if err := page.WaitForURL(func(url string) bool { return !strings.Contains(url, "/_admin/login") }); err != nil {
		log.Fatalf("wait login redirect: %v", err)
	}
}

func switchMockup(page playwright.Page, screen, tab string) {
	js := fmt.Sprintf(`(function(){ if(typeof show === 'function') show(%q); else { document.querySelectorAll('.screen').forEach(s => s.classList.toggle('active', s.dataset.screen === %q)); } })()`, screen, screen)
	if _, err := page.Evaluate(js); err != nil {
		log.Printf("show(%s) eval failed: %v", screen, err)
	}
	if tab != "" {
		tabJS := fmt.Sprintf(`(function(){ const el = document.querySelector('.nav-item[data-tab=%q]'); if (el) el.click(); document.querySelectorAll('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.tab === %q)); document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.dataset.tabPanel === %q)); })()`, tab, tab, tab)
		if _, err := page.Evaluate(tabJS); err != nil {
			log.Printf("tab(%s) eval failed: %v", tab, err)
		}
	}
	if _, err := page.WaitForFunction(`() => true`, nil, playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(200)}); err != nil {
		// ignore
	}
}

func shot(page playwright.Page, path string) {
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path:     playwright.String(path),
		FullPage: playwright.Bool(true),
	}); err != nil {
		log.Printf("shot %s: %v", path, err)
		return
	}
	fmt.Println("→", path)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
