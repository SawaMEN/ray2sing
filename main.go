package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
)

const maxInputBytes = 8 << 20 // Bound stdin/file input for the example CLI.

func readConfigInput(args []string, filePath string, stdin io.Reader) (string, error) {
	if filePath != "" && len(args) > 0 {
		return "", errors.New("use either -file or positional links, not both")
	}
	if len(args) > 0 {
		return strings.Join(args, "\n"), nil
	}

	var reader io.Reader = stdin
	if filePath != "" {
		file, err := os.Open(filePath)
		if err != nil {
			return "", err
		}
		defer file.Close()
		reader = file
	}
	if filePath == "" {
		if stat, err := os.Stdin.Stat(); err == nil && stat.Mode()&os.ModeCharDevice != 0 {
			return "", errors.New("provide one or more links, -file, or configuration text on stdin")
		}
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxInputBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxInputBytes {
		return "", fmt.Errorf("input exceeds the %d MiB limit", maxInputBytes>>20)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", errors.New("configuration input is empty")
	}
	return string(data), nil
}

func main() {
	file := flag.String("file", "", "read subscription links from this local file")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: ray2sing [-file path] [link ...] (or pipe links through stdin)\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	input, err := readConfigInput(flag.Args(), *file, os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Input error:", err)
		os.Exit(2)
	}

	output, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), input, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Conversion error:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(output, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "Output error:", err)
		os.Exit(1)
	}
}
