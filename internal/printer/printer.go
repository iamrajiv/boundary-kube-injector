package printer

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/boundary-kube-injector/internal/scope"
	"github.com/boundary-kube-injector/internal/target"
)

type Printer struct {
	writer *tabwriter.Writer
}

func New() *Printer {
	return &Printer{
		writer: tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0),
	}
}

func (p *Printer) PrintScopes(scopes []scope.ScopeInfo, scopeType string) {
	fmt.Printf("\n%s Scopes:\n", scopeType)
	fmt.Fprintln(p.writer, "ID\tName\tDescription")

	for _, scope := range scopes {
		fmt.Fprintf(p.writer, "%s\t%s\t%s\n", scope.ID, scope.Name, scope.Description)
	}

	p.writer.Flush()
}

func (p *Printer) PrintTargets(targets []target.TargetInfo) {
	fmt.Printf("\nTargets:\n")
	fmt.Fprintln(p.writer, "Name\tAliases\tActive Sessions\tType\tProject")

	for _, target := range targets {
		aliases := "none"
		if len(target.Aliases) > 0 {
			aliases = fmt.Sprintf("%v", target.Aliases)
		}

		fmt.Fprintf(p.writer, "%s\t%s\t%d\t%s\t%s\n",
			target.Name,
			aliases,
			target.ActiveSessions,
			target.Type,
			target.ProjectID,
		)
	}

	p.writer.Flush()
}
