package main

import (
	"fmt"
	"os"

	"github.com/UnitVectorY-Labs/oidcfinder/internal/oidcfinder"
)

func main() {
	if err := oidcfinder.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "oidcfinder: %v\n", err)
		os.Exit(1)
	}
}
