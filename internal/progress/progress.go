package progress

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	psio "github.com/pkositsyn/psi/internal/io"
)

type ReadResetCounter interface {
	psio.ReadResetter
	LinesRead() int
}

func TrackProgress(ctx context.Context, wg *sync.WaitGroup, msg string, files ...ReadResetCounter) {
	counters := make([]int, len(files))
	var totalLines int
	for _, file := range files {
		totalLines += psio.LineCount(file)
	}

	wg.Go(func() {
		var curCounter int
		for {
			select {
			case <-ctx.Done():
				lineLen := len(fmt.Sprintf("\r%s: %d/%d", msg, curCounter, totalLines))
				fmt.Printf("\r%s\r", strings.Repeat(" ", lineLen))
				return
			case <-time.After(time.Second):
			}

			for i, file := range files {
				num := file.LinesRead()

				curCounter += int(num) - counters[i]
				counters[i] = int(num)
			}

			fmt.Printf("\r%s: %d/%d", msg, curCounter, totalLines)
		}
	})
}
