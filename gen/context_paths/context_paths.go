// gen/context_paths generates the ignore paths for the user context since
// gin will not less apply the middleware to only specific paths.
//
// The generator reads every controller and looks for the //context:ignore comment.
// The format for the context ignore comment is:
//
// //contxt:ignore /api/mypath GET,POST
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"strings"
	"text/template"

	_ "embed"

	"golang.org/x/tools/go/packages"
)

//go:embed paths.tmpl
var pathsTmplSrc string

var pathsTmpl = template.Must(template.New("paths").Parse(pathsTmplSrc))

func main() {
	if err := run(); err != nil {
		fmt.Printf("Failed to generate: %s", err.Error())
		os.Exit(1)
	}
}

func run() error {
	// load pkg
	pkgConfig := &packages.Config{
		Mode: packages.NeedFiles,
	}

	pkgs, err := packages.Load(pkgConfig, "github.com/tinyauthapp/tinyauth/internal/controller")

	if err != nil {
		return fmt.Errorf("failed to load pkg: %w", err)
	}

	if len(pkgs) == 0 {
		return fmt.Errorf("failed to get controllers package")
	}

	pkg := pkgs[0]

	// for each file we check the comments and either add or remove the context
	var contextIgnorePaths []string

	for _, gofile := range pkg.GoFiles {
		// read the file
		file, err := os.ReadFile(gofile)

		if err != nil {
			fmt.Printf("Failed to read %s, ignoring", gofile)
			continue
		}

		// get the comment lines
		lines := strings.SplitSeq(string(file), "\n")

		for line := range lines {
			if !strings.HasPrefix(strings.TrimSpace(line), "//context:ignore") {
				continue
			}

			path, methods, ok := parseContextIgnoreLine(line)

			if !ok {
				fmt.Printf("Failed to parse %s rule, ignore", line)
				continue
			}

			for _, m := range methods {
				contextIgnorePaths = append(contextIgnorePaths, m+" "+path)
			}
		}
	}

	// generate out
	type tmplData struct {
		IgnorePaths []string
	}

	var buf bytes.Buffer

	if err := pathsTmpl.Execute(&buf, tmplData{
		IgnorePaths: contextIgnorePaths,
	}); err != nil {
		return err
	}

	formatted, err := format.Source(buf.Bytes())

	if err != nil {
		return fmt.Errorf("gofmt failed: %w", err)
	}

	// write out
	err = os.WriteFile("context_paths.go", formatted, 0666)

	if err != nil {
		return fmt.Errorf("failed to write out: %w", err)
	}

	return nil
}

func parseContextIgnoreLine(line string) (string, []string, bool) {
	line = strings.TrimPrefix(line, "//context:ignore ")
	path, methodStr, ok := strings.Cut(line, " ")
	if !ok {
		return "", []string{}, false
	}
	var methodsParsed []string
	methodParts := strings.SplitSeq(methodStr, ",")
	for m := range methodParts {
		if strings.TrimSpace(m) == "" {
			continue
		}
		m = strings.ToUpper(m)
		methodsParsed = append(methodsParsed, m)
	}
	return path, methodsParsed, true
}
