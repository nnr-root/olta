package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestNoBrandedHeaderReachesUpstream guards an OPSEC regression.
//
// The proxy previously set "X-Olta-Original-Host" on every request it
// forwarded to the target's real servers, via a misleadingly named
// getHomeDir() helper. Nothing ever read it back, so its only effect was to
// write this tool's name into the victim organization's web server, WAF, and
// SIEM logs — defeating the entire point of an AiTM proxy that is supposed to
// be indistinguishable from the genuine site.
//
// This scans the package source rather than driving a request, because the
// forwarding path lives inside closures built by NewHttpProxy that cannot be
// invoked without a live MITM listener. A source-level assertion still fails
// loudly if anyone reintroduces a branded header on the wire.
func TestNoBrandedHeaderReachesUpstream(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if strings.Contains(strings.ToLower(lit.Value), "x-olta") {
					t.Errorf("%s: branded header literal %s must never be sent upstream",
						fset.Position(lit.Pos()), lit.Value)
				}
				return true
			})
		}
	}
}
