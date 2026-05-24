package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ipanalytics/PrefixLint/internal/prefixlint"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "fix":
		os.Exit(runFix(os.Args[2:]))
	case "version":
		fmt.Println("prefixlint dev")
	default:
		usage()
		os.Exit(2)
	}
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var allow string
	var config string
	var format string
	var markdownOut string
	var failOn string
	fs.StringVar(&allow, "allow", "", "optional allow-list file used for conflict checks")
	fs.StringVar(&config, "config", "", "optional .prefixlintrc.json config file")
	fs.StringVar(&format, "format", "text", "report format: text, markdown, json, sarif")
	fs.StringVar(&markdownOut, "markdown-out", "", "write a markdown report to this file")
	fs.StringVar(&failOn, "fail-on", "warning", "minimum severity that fails: error, warning, info, none")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: prefixlint check [flags] <deny-list>")
		return 2
	}

	report, err := prefixlint.Check(prefixlint.CheckOptions{
		DenyPath:   fs.Arg(0),
		AllowPath:  allow,
		ConfigPath: config,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	out, err := prefixlint.RenderReport(report, format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Print(out)

	if markdownOut != "" {
		md, err := prefixlint.RenderReport(report, "markdown")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if err := os.WriteFile(markdownOut, []byte(md), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	threshold, err := prefixlint.ParseSeverityThreshold(failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if report.Fails(threshold) {
		return 1
	}
	return 0
}

func runFix(args []string) int {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	var inPlace bool
	fs.BoolVar(&inPlace, "w", false, "rewrite the input file")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: prefixlint fix [-w] <list>")
		return 2
	}

	fixed, err := prefixlint.FixFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if inPlace {
		if err := os.WriteFile(fs.Arg(0), []byte(fixed), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return 0
	}
	fmt.Print(fixed)
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, `prefixlint - lint and normalize IP blocklists

Usage:
  prefixlint check [--allow allow.txt] [--config .prefixlintrc.json] [--format text|markdown|json|sarif] [--fail-on warning] <deny-list>
  prefixlint fix [-w] <list>
  prefixlint version`)
}
