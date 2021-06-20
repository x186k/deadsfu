package main

import (
	xflag "flag"
	"fmt"
	"os"
	"reflect"
	"strings"
)

// order not important
var minmalUsage = []string{"urls", "https-private", "https-public", "all"}

var Usage = func() {
	fmt.Fprintf(xflag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	PrintDefaults(xflag.CommandLine, *helpAll)
}

func printFlagUsage(flag *xflag.Flag, f *xflag.FlagSet) {
	s := fmt.Sprintf("  -%s", flag.Name) // Two spaces before -; see next two comments.
	name, usage := xflag.UnquoteUsage(flag)
	if len(name) > 0 {
		s += " " + name
	}
	// Boolean flags of one ASCII letter are so common we
	// treat them specially, putting their usage on the same line.
	if len(s) <= 4 { // space, space, '-', 'x'.
		s += "\t"
	} else {
		// Four spaces before the tab triggers good alignment
		// for both 4- and 8-space tab stops.
		s += "\n    \t"
	}
	s += strings.ReplaceAll(usage, "\n", "\n    \t")

	if !isZeroValue(flag, flag.DefValue) {
		getter := flag.Value.(xflag.Getter)
		if _, ok := getter.Get().(string); ok {
			// put quotes on the value
			s += fmt.Sprintf(" (default %q)", flag.DefValue)
		} else {
			s += fmt.Sprintf(" (default %v)", flag.DefValue)
		}
	}
	fmt.Fprint(f.Output(), s, "\n")
}

func basicFlags(f *xflag.FlagSet) map[string]bool {

	m := make(map[string]bool)

	for _, v := range minmalUsage {
		if f.Lookup(v) == nil {
			panic(fmt.Errorf("Invalid basic flag name %s", v))
		}
		m[v] = true
	}
	return m
}

// PrintDefaults prints, to standard error unless configured otherwise, the
// default values of all defined command-line flags in the set. See the
// documentation for the global function PrintDefaults for more information.
func PrintDefaults(f *xflag.FlagSet, full bool) {

	basicNamemap := basicFlags(f)

	f.VisitAll(func(flag *xflag.Flag) {
		if full {
			printFlagUsage(flag, f)
		} else {
			if basicNamemap[flag.Name] {
				printFlagUsage(flag, f)
			}
		}
	})
}

// isZeroValue determines whether the string represents the zero
// value for a flag.
func isZeroValue(flag *xflag.Flag, value string) bool {
	// Build a zero value of the flag's Value type, and see if the
	// result of calling its String method equals the value passed in.
	// This works unless the Value type is itself an interface type.
	typ := reflect.TypeOf(flag.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Ptr {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	return value == z.Interface().(Value).String()
}

// Blah
type Value interface {
	String() string
	Set(string) error
}
