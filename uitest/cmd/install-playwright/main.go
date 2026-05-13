// install-playwright is a one-shot CLI that triggers playwright-go's
// browser-bundle download. Run once per machine before `make ui`.
// The binaries land in ~/.cache/ms-playwright/ and re-runs are
// no-ops, so it's safe to invoke from a setup script.
package main

import (
	"fmt"
	"os"

	"github.com/playwright-community/playwright-go"
)

func main() {
	if err := playwright.Install(&playwright.RunOptions{Browsers: []string{"chromium"}}); err != nil {
		fmt.Fprintln(os.Stderr, "playwright install:", err)
		os.Exit(1)
	}
	fmt.Println("ok")
}
