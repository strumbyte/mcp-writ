// go-runtime-mcp is a bounded, local stdio MCP fixture and its smoke-test client.
package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	var err error
	switch {
	case len(os.Args) == 1:
		err = newServer().Run(context.Background(), stdioTransport())
	case os.Args[1] == "probe":
		err = probe(os.Args[2:])
	default:
		err = fmt.Errorf("usage: %s [probe -help]", os.Args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
