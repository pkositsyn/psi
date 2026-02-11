package workerpool

import (
	"runtime"
	"sync"
)

type Result[V any] struct {
	Value V
	Error error
}

type WorkerPool[T any, V any] struct {
	handler     func(T) (V, error)
	tasksChan   chan []T
	resultsChan chan Result[V]
	wg          sync.WaitGroup
	numWorkers  int
}

func New[T any, V any](handler func(T) (V, error), numWorkersOpt ...int) *WorkerPool[T, V] {
	numWorkers := runtime.GOMAXPROCS(0)
	if len(numWorkersOpt) > 0 && numWorkersOpt[0] > 0 {
		numWorkers = numWorkersOpt[0]
	}
	
	pool := &WorkerPool[T, V]{
		handler:     handler,
		tasksChan:   make(chan []T, numWorkers),
		resultsChan: make(chan Result[V], numWorkers*2),
		numWorkers:  numWorkers,
	}

	for i := 0; i < numWorkers; i++ {
		pool.wg.Add(1)
		go pool.worker()
	}

	return pool
}

func (p *WorkerPool[T, V]) worker() {
	defer p.wg.Done()
	
	for tasks := range p.tasksChan {
		for _, task := range tasks {
			result, err := p.handler(task)
			p.resultsChan <- Result[V]{
				Value: result,
				Error: err,
			}
		}
	}
}

func (p *WorkerPool[T, V]) Add(tasks []T) {
	p.tasksChan <- tasks
}

func (p *WorkerPool[T, V]) Results() <-chan Result[V] {
	return p.resultsChan
}

func (p *WorkerPool[T, V]) Close() {
	close(p.tasksChan)
	
	go func() {
		p.wg.Wait()
		close(p.resultsChan)
	}()
}
