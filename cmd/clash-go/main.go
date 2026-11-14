// Command clash-go is the Clash Go desktop app.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/neko233-com/netflow/internal/app"
	"github.com/neko233-com/netflow/internal/validation"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--internal-validate" {
		if err := validation.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := app.New(app.Options{}).Run(); err != nil {
		log.Fatal(err)
	}
}
