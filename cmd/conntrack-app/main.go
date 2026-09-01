// Command conntrack-app is the native desktop wrapper: a WKWebView window
// (via webview_go) around the exact same backend cmd/conntrackd serves in
// plain-browser mode, listening on a random local port instead of a fixed
// one. Mirrors NSELocalSSH's cmd/nse-app. macOS only — see
// scripts/package-macos.sh.
package main

import (
	"context"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os/exec"

	webview "github.com/webview/webview_go"

	"conntrackd/internal/appserver"
)

func main() {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("ConnTrack")
	w.SetSize(1360, 900, webview.HintNone)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app, err := appserver.New(ctx, "")
	if err != nil {
		w.SetHtml(errorHTML("Could not start ConnTrack", err.Error()))
		w.Run()
		return
	}
	defer app.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.SetHtml(errorHTML("Could not start the local dashboard server", err.Error()))
		w.Run()
		return
	}
	defer ln.Close()

	go func() {
		if err := http.Serve(ln, app.Handler); err != nil && err != http.ErrServerClosed {
			log.Printf("dashboard server: %v", err)
		}
	}()

	url := "http://" + ln.Addr().String()

	// Exposed to the page as window.conntrackOpenInBrowser() — the "Open
	// in Browser" button in the header calls this to hand the same running
	// session off to the system default browser. Additive, not a mode
	// switch: this window and its server keep running regardless of what
	// happens to that browser tab.
	if err := w.Bind("conntrackOpenInBrowser", func() {
		if err := exec.Command("open", url).Start(); err != nil {
			log.Printf("open in browser: %v", err)
		}
	}); err != nil {
		log.Printf("bind conntrackOpenInBrowser: %v", err)
	}

	log.Printf("ConnTrack desktop app serving %s", url)
	w.Navigate(url)
	w.Run()
}

func errorHTML(title, detail string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ConnTrack</title>
<style>
body{font:15px/1.45 -apple-system,BlinkMacSystemFont,sans-serif;background:#14161a;color:#e6e9ef;margin:0;padding:48px}
h1{font-size:22px;margin:0 0 12px}
p{color:#8b93a3;max-width:42rem}
</style></head>
<body><h1>%s</h1><p>%s</p></body></html>`, html.EscapeString(title), html.EscapeString(detail))
}
