package scan

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// TestWorkerPoolNoDeadlock verifies that submitting more jobs than worker buffer size does not deadlock.
func TestWorkerPoolNoDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const numWorkers = 5
	const totalJobs = 100 // Exceeds worker buffer size (numWorkers * 2 = 10)

	var processedCount atomic.Int32

	// Create worker pool with mock scanFunc
	pool := NewWorkerPool(ctx, numWorkers, func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error) {
		processedCount.Add(1)
		return nil, nil
	})

	doneCollecting := make(chan struct{})
	go func() {
		defer close(doneCollecting)
		for range pool.Results() {
			// Drain results
		}
	}()

	pool.Start()

	// Submit jobs
	for i := 0; i < totalJobs; i++ {
		node := &types.DependencyNode{
			Name:    fmt.Sprintf("pkg-%d", i),
			Version: "1.0.0",
		}
		if !pool.Submit(ScanJob{
			Node:    node,
			NodeKey: node.Name + "@" + node.Version,
		}) {
			t.Fatalf("failed to submit job %d", i)
		}
	}

	pool.Close()
	<-doneCollecting

	if int(processedCount.Load()) != totalJobs {
		t.Errorf("expected %d processed jobs, got %d", totalJobs, processedCount.Load())
	}
}
