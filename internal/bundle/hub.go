package bundle

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Hub wakes long polls waiting on a bundle. Revisions change in Postgres; Listen turns the
// NOTIFY that every write issues into Notify calls, so all replicas wake, not only the writer.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]struct{}
}

func NewHub() *Hub { return &Hub{subs: map[string]map[chan struct{}]struct{}{}} }

// Subscribe returns a channel that receives when the bundle may have changed.
func (h *Hub) Subscribe(name string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	if h.subs[name] == nil {
		h.subs[name] = map[chan struct{}]struct{}{}
	}
	h.subs[name][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs[name], ch)
		if len(h.subs[name]) == 0 {
			delete(h.subs, name)
		}
		h.mu.Unlock()
	}
}

func (h *Hub) Notify(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[name] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// NotifyAll wakes every waiter; used after (re)connecting, when notifications may have been missed.
func (h *Hub) NotifyAll() {
	h.mu.Lock()
	names := make([]string, 0, len(h.subs))
	for n := range h.subs {
		names = append(names, n)
	}
	h.mu.Unlock()
	for _, n := range names {
		h.Notify(n)
	}
}

// Listen forwards Postgres notifications on channel to the hub until ctx ends, reconnecting on error.
func Listen(ctx context.Context, pool *pgxpool.Pool, channel string, h *Hub, log *slog.Logger) {
	for ctx.Err() == nil {
		err := listenOnce(ctx, pool, channel, h)
		if ctx.Err() != nil {
			return
		}
		log.Error("bundle notifications interrupted, reconnecting", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func listenOnce(ctx context.Context, pool *pgxpool.Pool, channel string, h *Hub) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	h.NotifyAll()
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			// The connection's state is unknown after an error; don't return it to the pool.
			_ = conn.Conn().Close(context.WithoutCancel(ctx))
			return err
		}
		h.Notify(n.Payload)
	}
}
