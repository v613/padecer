package shutdown

import (
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	t       time.Duration
	wg      sync.WaitGroup
	running atomic.Bool
}

func NewManager(t time.Duration) *Manager {
	mgr := &Manager{t: t}
	mgr.running.Store(true)
	return mgr
}

func (m *Manager) Shutdown() {m.running.Store(false)}
func (m *Manager) IsShuttingDown() bool {return !m.running.Load()}
func (m *Manager) Add(delta int) {m.wg.Add(delta)}
func (m *Manager) Done() {m.wg.Done()}

func (m *Manager) Wait() {
	done := make(chan struct{})
	
	go func() {
		m.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
	case <-time.After(m.t):
	}
}