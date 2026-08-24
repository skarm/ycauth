package ycauth //nolint:testpackage

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain fails the package when a refresh goroutine outlives the tests that
// started it. Cache is the only type here that spawns goroutines, so the check
// looks for its frames by name instead of counting goroutines, which keeps it
// immune to the testing package's own background work.
func TestMain(m *testing.M) {
	code := m.Run()

	if code == 0 {
		if leaked := findLeakedRefreshes(); leaked != "" {
			_, _ = fmt.Fprintf(os.Stderr, "leaked refresh goroutines:\n%s\n", leaked)
			code = 1
		}
	}

	os.Exit(code)
}

// findLeakedRefreshes returns stack blocks for refresh goroutines that survived
// the test suite.
func findLeakedRefreshes() string {
	deadline := time.Now().Add(5 * time.Second)

	for {
		stacks := goroutineStacks()
		leaked := make([]string, 0, 1)

		for stack := range strings.SplitSeq(stacks, "\n\n") {
			if strings.Contains(stack, "ycauth.(*Cache).runRefresh") {
				leaked = append(leaked, stack)
			}
		}

		if len(leaked) == 0 {
			return ""
		}

		if time.Now().After(deadline) {
			return strings.Join(leaked, "\n\n")
		}

		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
}

// goroutineStacks captures all goroutine stacks, growing the buffer until the
// runtime reports that the snapshot fits.
func goroutineStacks() string {
	buffer := make([]byte, 64<<10)
	for {
		written := runtime.Stack(buffer, true)
		if written < len(buffer) {
			return string(buffer[:written])
		}
		buffer = make([]byte, 2*len(buffer))
	}
}
