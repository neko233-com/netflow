// Command clash-go is the Clash Go desktop app.
package main

import (
	"log"

	"github.com/neko233-com/netflow/internal/app"
)

func main() {
	if err := app.New(app.Options{}).Run(); err != nil {
		log.Fatal(err)
	}
}
