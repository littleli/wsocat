//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"wsocat/internal/endpoint"
)

const version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runContext(ctx, args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 {
		switch args[0] {
		case "-h", "--help":
			fmt.Fprintln(stdout, "Usage: wsocat.exe [address1] [address2]")
			fmt.Fprintln(stdout, "Windows-only bidirectional stream relay.")
			fmt.Fprintln(stdout, "Supported types: STDIO, TCP, TCP-LISTEN, TLS, NPIPE, NPIPE-LISTEN, EXEC, WSL, UNIX, UNIX-LISTEN, HVSOCK, HVSOCK-LISTEN, SP")
			return 0
		case "--version":
			fmt.Fprintf(stdout, "wsocat %s\n", version)
			return 0
		}
	}

	if len(args) != 2 {
		fmt.Fprintln(stderr, "Usage: wsocat.exe [address1] [address2]")
		return 2
	}

	source, err := endpoint.Parse(args[0], endpoint.Source)
	if err != nil {
		fmt.Fprintf(stderr, "wsocat: address1: %v\n", err)
		return 2
	}
	target, err := endpoint.Parse(args[1], endpoint.Target)
	if err != nil {
		fmt.Fprintf(stderr, "wsocat: address2: %v\n", err)
		return 2
	}
	if err := endpoint.ValidatePair(source, target); err != nil {
		fmt.Fprintf(stderr, "wsocat: %v\n", err)
		return 2
	}
	if err := endpoint.Run(ctx, source, target, os.Stdin, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "wsocat: %v\n", err)
		return 1
	}
	return 0
}
