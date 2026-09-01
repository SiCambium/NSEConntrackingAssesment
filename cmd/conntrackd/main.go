// Command conntrackd runs conntrackd in plain-browser mode: it starts the
// same backend as cmd/conntrack-app but serves it as an ordinary local
// HTTP server, with no native window — open the printed URL in any
// browser. See PLAN.md for the full design and README.md for setup.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"conntrackd/internal/appserver"
	"conntrackd/internal/config"
)

func main() {
	configPath := flag.String("config", "", "path to config.yaml (default: OS app-support dir; see -print-data-dir)")
	printDataDir := flag.Bool("print-data-dir", false, "print the resolved data directory and exit")
	flag.Parse()

	if *printDataDir {
		dir, err := config.DataDir()
		if err != nil {
			log.Fatalf("resolving data dir: %v", err)
		}
		os.Stdout.WriteString(dir + "\n")
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app, err := appserver.New(ctx, *configPath)
	if err != nil {
		log.Fatalf("starting conntrackd: %v", err)
	}
	defer app.Close()

	if len(app.Config.Get().Firewalls) == 0 {
		log.Printf("conntrackd: no firewalls configured yet — add one from the Settings tab in the dashboard")
	}

	addr := app.Config.Get().Addr()
	httpServer := &http.Server{Addr: addr, Handler: app.Handler}
	go func() {
		log.Printf("conntrackd: dashboard listening on http://%s", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("conntrackd: shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
}
