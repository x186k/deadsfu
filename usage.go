package main

import (

	//xflag "flag"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

// order not important
//var minmalUsage = []string{"https-url", "http-url", "https-auto", "all"}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])

	fmt.Fprintf(os.Stderr, "At a minimum, -s (-https-url) or -p (-http-url) are required\n\n")

	if *helpAll {
		pflag.PrintDefaults()
	} else {

		fs := pflag.NewFlagSet("foo", pflag.ExitOnError)
		fs.SortFlags = false
		fs.AddFlag(pflag.CommandLine.Lookup("https-url"))
		fs.AddFlag(pflag.CommandLine.Lookup("https-auto"))
		fs.AddFlag(pflag.CommandLine.Lookup("http-url"))
		fs.AddFlag(pflag.CommandLine.ShorthandLookup("a"))
		fs.PrintDefaults()

		// printFlagUsage("all", os.Stderr)
		// printFlagUsage("https-url", os.Stderr)
		// printFlagUsage("https-auto", os.Stderr)
		// printFlagUsage("http-url", os.Stderr)

	}
}
