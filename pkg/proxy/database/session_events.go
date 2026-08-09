package database

// SessionCaptureListener receives a private cloned session snapshot after
// cookie tokens are captured. Listeners must return promptly; background
// services should perform only a non-blocking enqueue from this callback.
type SessionCaptureListener func(*Session)

// SubscribeSessionCaptures registers a listener and returns an idempotent
// unsubscribe function.
func (d *Database) SubscribeSessionCaptures(listener SessionCaptureListener) func() {
	if d == nil || listener == nil {
		return func() {}
	}
	d.captureMu.Lock()
	d.nextCaptureID++
	id := d.nextCaptureID
	d.captureListeners[id] = listener
	d.captureMu.Unlock()

	var unsubscribed bool
	return func() {
		d.captureMu.Lock()
		if !unsubscribed {
			delete(d.captureListeners, id)
			unsubscribed = true
		}
		d.captureMu.Unlock()
	}
}

func (d *Database) publishSessionCapture(sessionID string) {
	d.stateMu.RLock()
	session, exists := d.sessionsBySID[sessionID]
	if !exists {
		d.stateMu.RUnlock()
		return
	}
	snapshot := cloneSession(session)
	d.stateMu.RUnlock()

	d.captureMu.RLock()
	listeners := make([]SessionCaptureListener, 0, len(d.captureListeners))
	for _, listener := range d.captureListeners {
		listeners = append(listeners, listener)
	}
	d.captureMu.RUnlock()
	for _, listener := range listeners {
		listener(cloneSession(snapshot))
	}
}
