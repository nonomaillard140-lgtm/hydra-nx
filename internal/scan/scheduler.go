package scan

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"hydra/internal/store"
)

type Scheduler struct {
	store   *store.Store
	scanner *Scanner
	queue   chan int64
	workers int
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	queued  map[int64]struct{}
}

func NewScheduler(st *store.Store, workers, timeoutSeconds, hostLimit int) *Scheduler {
	if workers < 1 {
		workers = 4
	}
	if timeoutSeconds < 2 {
		timeoutSeconds = 12
	}
	return &Scheduler{store: st, scanner: NewScanner(st, time.Duration(timeoutSeconds)*time.Second, hostLimit), queue: make(chan int64, 1024), workers: workers, queued: make(map[int64]struct{})}
}

func (s *Scheduler) Scanner() *Scanner { return s.scanner }

func (s *Scheduler) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx)
	}
	queued, err := s.store.QueuedCracks(ctx)
	if err != nil {
		slog.Error("reprise des scans", "error", err)
	}
	for _, crack := range queued {
		if err := s.Submit(crack.ID); err != nil {
			slog.Error("reprise d'un scan", "crack", crack.ID, "error", err)
		}
	}
}

func (s *Scheduler) Submit(id int64) error {
	s.mu.Lock()
	if _, exists := s.queued[id]; exists {
		s.mu.Unlock()
		return nil
	}
	s.queued[id] = struct{}{}
	s.mu.Unlock()
	select {
	case s.queue <- id:
		return nil
	default:
		s.mu.Lock()
		delete(s.queued, id)
		s.mu.Unlock()
		return errors.New("file de scans pleine")
	}
}

func (s *Scheduler) worker(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-s.queue:
			s.mu.Lock()
			delete(s.queued, id)
			s.mu.Unlock()
			if err := s.scanner.RunCrack(ctx, id); err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("scan terminé en erreur", "crack", id, "error", err)
				_ = s.store.SetCrackStatus(context.WithoutCancel(ctx), id, "failed", store.MarshalJSON(map[string]string{"error": err.Error()}))
			}
		}
	}
}

func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Scheduler) Depth() int { return len(s.queue) }
