package target

type TargetInfo struct {
	ID             string
	Name           string
	Aliases        []string
	ActiveSessions int
	Type           string
	ProjectID      string
}
