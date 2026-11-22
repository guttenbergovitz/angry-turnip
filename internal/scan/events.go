package scan

import "time"

// Stage identifies an observable phase of the Angry Turnip security assessment pipeline.
type Stage string

const (
	StageDiscovery   Stage = "discovery"
	StageResolution  Stage = "resolution"
	StageSCA         Stage = "sca"
	StageEnrichment  Stage = "enrichment"
	StageThreatIntel Stage = "threat-intel"
	StageSecrets     Stage = "secrets"
	StageIaC         Stage = "iac"
	StageLicences    Stage = "licences"
	StagePolicy      Stage = "policy"
)

// StageStatus describes the current execution state of a pipeline stage.
type StageStatus string

const (
	StagePending   StageStatus = "pending"
	StageRunning   StageStatus = "running"
	StageCompleted StageStatus = "completed"
	StagePartial   StageStatus = "partial"
	StageFailed    StageStatus = "failed"
	StageSkipped   StageStatus = "skipped"
)

// ScanEvent carries typed, observable progress and provenance for a pipeline stage.
type ScanEvent struct {
	Stage     Stage
	Status    StageStatus
	Current   int
	Total     *int // nil when total work items are indeterminate
	Queued    int
	Active    int
	Failed    int
	Skipped   int
	Workers   int
	Message   string
	Error     string
	Timestamp time.Time
}

// StageReporter is an optional extension of ProgressReporter that receives typed stage events.
type StageReporter interface {
	OnStageEvent(ev ScanEvent)
}

func emitStage(reporter ProgressReporter, ev ScanEvent) {
	if reporter == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if sr, ok := reporter.(StageReporter); ok {
		sr.OnStageEvent(ev)
	}
}

func intPtr(v int) *int {
	return &v
}
