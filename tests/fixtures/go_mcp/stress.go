package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

type StressInput struct {
	Workers  int `json:"workers" jsonschema:"Concurrent OS threads, 1 to 16"`
	Rounds   int `json:"rounds" jsonschema:"Allocation rounds per worker, 1 to 32"`
	AllocKiB int `json:"allocKiB" jsonschema:"Allocation size per round, 1 to 256 KiB"`
}

type StressOutput struct {
	Workers        int    `json:"workers"`
	Iterations     int    `json:"iterations"`
	AllocatedBytes uint64 `json:"allocatedBytes"`
	GCCycles       uint32 `json:"gcCycles"`
	Checksum       uint64 `json:"checksum"`
}

func stress(ctx context.Context, in StressInput) (StressOutput, error) {
	if in.Workers < 1 || in.Workers > 16 || in.Rounds < 1 || in.Rounds > 32 || in.AllocKiB < 1 || in.AllocKiB > 256 {
		return StressOutput{}, fmt.Errorf("workers must be 1..16, rounds 1..32, allocKiB 1..256")
	}
	if err := ctx.Err(); err != nil {
		return StressOutput{}, err
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var ready sync.WaitGroup
	ready.Add(in.Workers)
	start := make(chan struct{})
	type result struct {
		checksum uint64
		err      error
	}
	results := make(chan result, in.Workers)
	for worker := 0; worker < in.Workers; worker++ {
		go func() {
			// Holding all workers at the barrier exercises real OS thread creation.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready.Done()
			<-start
			sum, err := stressWorker(ctx, in, worker)
			results <- result{sum, err}
		}()
	}
	ready.Wait()
	close(start)
	out := StressOutput{Workers: in.Workers, Iterations: in.Workers * in.Rounds}
	var firstErr error
	for range in.Workers {
		r := <-results
		out.Checksum += r.checksum
		if firstErr == nil {
			firstErr = r.err
		}
	}
	if firstErr != nil {
		return StressOutput{}, firstErr
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	out.GCCycles = after.NumGC - before.NumGC
	out.AllocatedBytes = uint64(out.Iterations) * uint64(in.AllocKiB) * 1024
	return out, nil
}

func stressWorker(ctx context.Context, in StressInput, worker int) (uint64, error) {
	// At the maximum input, at most 128 MiB of payload is retained across workers.
	held := make([][]byte, 0, in.Rounds)
	var sum uint64
	for round := 0; round < in.Rounds; round++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		buf := make([]byte, in.AllocKiB*1024)
		for i := range buf {
			buf[i] = byte(i + worker + round)
		}
		held = append(held, buf)
		sum += growStack(32, byte(worker+round), round == 0)
		for _, value := range buf {
			sum += uint64(value)
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
	runtime.KeepAlive(held)
	return sum, nil
}

//go:noinline
func growStack(depth int, seed byte, collect bool) uint64 {
	var frame [1024]byte
	for i := range frame {
		frame[i] = seed + byte(i)
	}
	var sum uint64
	if depth > 0 {
		sum = growStack(depth-1, seed+1, collect)
	} else if collect {
		// Run GC while the expanded stacks are still live.
		runtime.GC()
	}
	for _, value := range frame {
		sum += uint64(value)
	}
	return sum
}
