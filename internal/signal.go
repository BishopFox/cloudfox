package internal

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"
)

// signalOnce ensures we only register the SIGINT handler once per process,
// even if multiple cloud providers call SetupSignalHandler.
var signalOnce sync.Once

// signalCancel is the cancel function for the process-wide signal context.
var signalCancel context.CancelFunc

// signalCtx is the process-wide cancellable context.
var signalCtx context.Context

// SetupSignalHandler sets up a process-wide Ctrl+C handler with double-press
// confirmation to prevent accidental shutdowns of long-running commands.
//
// First Ctrl+C: prints a warning and starts a 5-second confirmation window.
// Second Ctrl+C within 5s: cancels the returned context (graceful shutdown).
// Third Ctrl+C: calls os.Exit(1) (force exit).
// If the 5s window expires without a second press, resets to initial state.
//
// Returns a context that is cancelled on confirmed graceful shutdown.
// Safe to call multiple times; only the first call registers the handler.
func SetupSignalHandler() context.Context {
	signalOnce.Do(func() {
		signalCtx, signalCancel = context.WithCancel(context.Background())

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			for {
				<-sigCh
				fmt.Printf("\n[cloudfox] Press Ctrl+C again within 5 seconds to gracefully shut down.\n")

				select {
				case <-sigCh:
					// Second Ctrl+C within window: graceful shutdown
					fmt.Printf("[cloudfox] Shutting down gracefully, finishing in-flight requests and writing partial results...\n")
					fmt.Printf("[cloudfox] Press Ctrl+C again to force exit.\n")
					signalCancel()
					<-sigCh
					fmt.Printf("\n[cloudfox] Force exit.\n")
					os.Exit(1)
				case <-time.After(5 * time.Second):
					// Window expired, reset
					fmt.Printf("[cloudfox] Shutdown cancelled. Resuming...\n")
					continue
				}
			}
		}()
	})
	return signalCtx
}
