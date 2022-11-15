package types

import (
	"context"

	"github.com/future-architect/vuls/pkg/types"
)

type Analyzer interface {
	Name() string
	Analyze(context.Context, *AnalyzerHost) error
}

type AnalyzerHost struct {
	Host      *types.Host
	Analyzers []Analyzer
}
