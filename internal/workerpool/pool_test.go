package workerpool

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestWorkerPoolBasic(t *testing.T) {
	handler := func(x int) (int, error) {
		return x * 2, nil
	}

	pool := New(handler)

	tasks := []int{1, 2, 3, 4, 5}
	pool.Add(tasks)
	pool.Close()

	results := make(map[int]bool)
	for result := range pool.Results() {
		if result.Error != nil {
			t.Errorf("unexpected error: %v", result.Error)
		}
		results[result.Value] = true
	}

	expected := map[int]bool{2: true, 4: true, 6: true, 8: true, 10: true}
	if len(results) != len(expected) {
		t.Errorf("expected %d results, got %d", len(expected), len(results))
	}

	for val := range expected {
		if !results[val] {
			t.Errorf("expected result %d not found", val)
		}
	}
}

func TestWorkerPoolWithErrors(t *testing.T) {
	handler := func(x int) (int, error) {
		if x < 0 {
			return 0, errors.New("negative number")
		}
		return x * 2, nil
	}

	pool := New(handler)

	tasks := []int{1, -2, 3, -4, 5}
	pool.Add(tasks)
	pool.Close()

	var results []int
	var errs []error

	for result := range pool.Results() {
		if result.Error != nil {
			errs = append(errs, result.Error)
		} else {
			results = append(results, result.Value)
		}
	}

	if len(results) != 3 {
		t.Errorf("expected 3 successful results, got %d", len(results))
	}

	if len(errs) != 2 {
		t.Errorf("expected 2 errors, got %d", len(errs))
	}
}

func TestWorkerPoolMultipleAdds(t *testing.T) {
	handler := func(x int) (int, error) {
		return x + 1, nil
	}

	pool := New(handler)

	pool.Add([]int{1, 2, 3})
	pool.Add([]int{4, 5, 6})
	pool.Add([]int{7, 8, 9})
	
	pool.Close()

	count := 0
	for range pool.Results() {
		count++
	}

	if count != 9 {
		t.Errorf("expected 9 results, got %d", count)
	}
}

func TestWorkerPoolConcurrency(t *testing.T) {
	processed := sync.Map{}
	
	handler := func(x int) (int, error) {
		time.Sleep(10 * time.Millisecond)
		processed.Store(x, true)
		return x, nil
	}

	pool := New(handler)

	numTasks := 100
	batchSize := 10
	
	for i := 0; i < numTasks; i += batchSize {
		batch := make([]int, batchSize)
		for j := 0; j < batchSize; j++ {
			batch[j] = i + j
		}
		pool.Add(batch)
	}
	
	pool.Close()

	done := make(chan struct{})
	go func() {
		for range pool.Results() {
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Minute):
		t.Fatal("тест завис - возможен дедлок")
	}

	count := 0
	processed.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	if count != numTasks {
		t.Errorf("expected %d tasks processed, got %d", numTasks, count)
	}
}

func TestWorkerPoolStringToInt(t *testing.T) {
	handler := func(s string) (int, error) {
		return len(s), nil
	}

	pool := New(handler)

	tasks := []string{"hello", "world", "foo", "bar"}
	pool.Add(tasks)
	pool.Close()

	sum := 0
	for result := range pool.Results() {
		if result.Error != nil {
			t.Errorf("unexpected error: %v", result.Error)
		}
		sum += result.Value
	}

	expectedSum := 5 + 5 + 3 + 3
	if sum != expectedSum {
		t.Errorf("expected sum %d, got %d", expectedSum, sum)
	}
}

func TestWorkerPoolEmptyTasks(t *testing.T) {
	handler := func(x int) (int, error) {
		return x, nil
	}

	pool := New(handler)
	pool.Close()

	count := 0
	for range pool.Results() {
		count++
	}

	if count != 0 {
		t.Errorf("expected 0 results for empty tasks, got %d", count)
	}
}

func TestWorkerPoolCustomWorkers(t *testing.T) {
	handler := func(x int) (int, error) {
		return x * 2, nil
	}

	pool := New(handler, 3)

	if pool.numWorkers != 3 {
		t.Errorf("expected 3 workers, got %d", pool.numWorkers)
	}

	tasks := []int{1, 2, 3, 4, 5}
	pool.Add(tasks)
	pool.Close()

	count := 0
	for range pool.Results() {
		count++
	}

	if count != 5 {
		t.Errorf("expected 5 results, got %d", count)
	}
}

func TestWorkerPoolDefaultWorkers(t *testing.T) {
	handler := func(x int) (int, error) {
		return x, nil
	}

	pool := New(handler)

	if pool.numWorkers != runtime.GOMAXPROCS(0) {
		t.Errorf("expected GOMAXPROCS workers, got %d", pool.numWorkers)
	}

	pool.Close()
}
