package scan

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

type HostLimiter struct {
	mu      sync.Mutex
	limit   int
	holders map[string]chan struct{}
}

func NewHostLimiter(limit int) *HostLimiter {
	if limit < 1 {
		limit = 2
	}
	return &HostLimiter{limit: limit, holders: make(map[string]chan struct{})}
}

func (l *HostLimiter) Acquire(ctx context.Context, host string) (func(), error) {
	l.mu.Lock()
	holder, ok := l.holders[host]
	if !ok {
		holder = make(chan struct{}, l.limit)
		l.holders[host] = holder
	}
	l.mu.Unlock()
	jitter := time.NewTimer(time.Duration(rand.Intn(120)) * time.Millisecond)
	defer jitter.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-jitter.C:
	}
	select {
	case holder <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-holder }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
