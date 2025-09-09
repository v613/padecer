package shutdown

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewManager(t *testing.T) {
	timeout := 30 * time.Second
	mgr := NewManager(timeout)

	if mgr.t != timeout {
		t.Errorf("Expected timeout to be %v, got %v", timeout, mgr.t)
	}

	if mgr.IsShuttingDown() {
		t.Errorf("Manager should not be shutting down initially")
	}
}

func TestManager_Shutdown(t *testing.T) {
	mgr := NewManager(30 * time.Second)

	if mgr.IsShuttingDown() {
		t.Errorf("Manager should not be shutting down initially")
	}

	mgr.Shutdown()

	if !mgr.IsShuttingDown() {
		t.Errorf("Manager should be shutting down after Shutdown() call")
	}

	mgr.Shutdown()
	mgr.Shutdown()

	if !mgr.IsShuttingDown() {
		t.Errorf("Manager should still be shutting down after multiple Shutdown() calls")
	}
}

func TestManager_AddDone(t *testing.T) {
	mgr := NewManager(5 * time.Second)

	mgr.Add(1)
	mgr.Done()

	done := make(chan struct{})
	go func() {
		mgr.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Errorf("Wait() took too long when WaitGroup should be at zero")
	}
}

func TestManager_Wait_WithTimeout(t *testing.T) {
	mgr := NewManager(100 * time.Millisecond)
	
	mgr.Add(1)
	
	start := time.Now()
	mgr.Wait()
	elapsed := time.Since(start)
	
	if elapsed < 90*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Errorf("Wait() took %v, expected around 100ms", elapsed)
	}
}

func TestManager_Wait_CompletesEarly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mgr := NewManager(5 * time.Second)

		mgr.Add(1)

		go func() {
			time.Sleep(100 * time.Millisecond)
			mgr.Done()
		}()

		start := time.Now()
		mgr.Wait()
		elapsed := time.Since(start)

		if elapsed != 100*time.Millisecond {
			t.Errorf("Wait() took %v, expected exactly 100ms", elapsed)
		}
	})
}

func TestManager_ConcurrentAddDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mgr := NewManager(5 * time.Second)

		const numGoroutines = 100
		var wg sync.WaitGroup

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mgr.Add(1)
				time.Sleep(10 * time.Millisecond)
				mgr.Done()
			}()
		}

		wg.Wait()

		start := time.Now()
		mgr.Wait()
		elapsed := time.Since(start)

		if elapsed != 0 {
			t.Errorf("Wait() took %v, expected immediate completion", elapsed)
		}
	})
}

func TestManager_ShutdownDuringWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mgr := NewManager(5 * time.Second)

		mgr.Add(1)

		go func() {
			time.Sleep(50 * time.Millisecond)
			mgr.Shutdown()
		}()

		time.Sleep(100 * time.Millisecond)
		if !mgr.IsShuttingDown() {
			t.Errorf("Manager should be shutting down")
		}

		mgr.Done()

		start := time.Now()
		mgr.Wait()
		elapsed := time.Since(start)

		if elapsed != 0 {
			t.Errorf("Wait() took %v, expected immediate completion after Done()", elapsed)
		}
	})
}

func TestManager_MultipleWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mgr := NewManager(2 * time.Second)

		const numWorkers = 10
		workDuration := 100 * time.Millisecond

		for i := 0; i < numWorkers; i++ {
			mgr.Add(1)
			go func(id int) {
				defer mgr.Done()
				time.Sleep(workDuration)
			}(i)
		}

		start := time.Now()
		mgr.Wait()
		elapsed := time.Since(start)

		if elapsed != workDuration {
			t.Errorf("Wait() took %v, expected exactly %v", elapsed, workDuration)
		}
	})
}

func TestManager_ZeroTimeout(t *testing.T) {
	mgr := NewManager(0)

	mgr.Add(1)

	start := time.Now()
	mgr.Wait()
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Wait() with zero timeout took %v, expected immediate return", elapsed)
	}

	mgr.Done()
}

func TestManager_IsShuttingDown_ThreadSafe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mgr := NewManager(5 * time.Second)

		const numGoroutines = 50
		var wg sync.WaitGroup
		results := make([]bool, numGoroutines*2)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(2)
			go func(idx int) {
				defer wg.Done()
				results[idx*2] = mgr.IsShuttingDown()
			}(i)
			go func(idx int) {
				defer wg.Done()
				results[idx*2+1] = mgr.IsShuttingDown()
			}(i)
		}

		time.Sleep(10 * time.Millisecond)
		mgr.Shutdown()

		wg.Wait()

		shutdownTriggered := false
		for _, result := range results {
			if result {
				shutdownTriggered = true
				break
			}
		}

		if !mgr.IsShuttingDown() {
			t.Errorf("Manager should be in shutdown state after Shutdown() call")
		}

		_ = shutdownTriggered
	})
}
