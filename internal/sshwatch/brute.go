package sshwatch

import (
	"sync"
	"time"
)

// BruteDetector flags an IP whose failed attempts exceed Threshold within
// Window. Each IP alerts once per quiet period: after firing, it must fall
// silent for a full Window before it can fire again, preventing alert spam
// during an ongoing attack.
//
// State is kept only for IPs seen within the last Window or so: an
// internet-facing sshd sees thousands of distinct scanner IPs a day, and the
// agent runs for months under a small memory ceiling.
type BruteDetector struct {
	Window    time.Duration
	Threshold int

	mu        sync.Mutex
	attempts  map[string][]time.Time
	fired     map[string]time.Time
	lastSweep time.Time
}

// NewBruteDetector returns a detector with the given window and threshold.
func NewBruteDetector(window time.Duration, threshold int) *BruteDetector {
	return &BruteDetector{
		Window: window, Threshold: threshold,
		attempts: map[string][]time.Time{},
		fired:    map[string]time.Time{},
	}
}

// Record registers a failed attempt and reports whether this attempt
// crosses the threshold (i.e. the caller should alert now).
func (b *BruteDetector) Record(ip string, at time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if at.Sub(b.lastSweep) >= b.Window {
		b.prune(at)
		b.lastSweep = at
	}

	cutoff := at.Add(-b.Window)
	kept := b.attempts[ip][:0]
	for _, t := range b.attempts[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, at)
	b.attempts[ip] = kept

	if len(kept) < b.Threshold {
		return false
	}
	if last, ok := b.fired[ip]; ok && at.Sub(last) < b.Window {
		b.fired[ip] = at // attack continues; slide the quiet period forward
		return false
	}
	b.fired[ip] = at
	return true
}

// Count returns the attempts currently inside the window for an IP.
func (b *BruteDetector) Count(ip string, now time.Time) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	cutoff := now.Add(-b.Window)
	for _, t := range b.attempts[ip] {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

// prune forgets every IP whose newest attempt has left the window. Callers
// hold b.mu. Newest is the max timestamp in the slice, not the last element,
// so out-of-order Record times cannot drop an IP that still has in-window
// attempts.
//
// Forgetting such an IP cannot change a later decision. Its attempts would
// be filtered out by the next Record anyway, and its fired time is never
// later than its newest attempt, so it is outside the quiet period too:
// the IP is free to fire again, exactly as if it had never been seen.
func (b *BruteDetector) prune(now time.Time) {
	cutoff := now.Add(-b.Window)
	for ip, times := range b.attempts {
		if len(times) == 0 || !newestAttempt(times).After(cutoff) {
			delete(b.attempts, ip)
			delete(b.fired, ip)
		}
	}
}

// newestAttempt returns the latest timestamp in times. Record does not require
// chronological order, so prune must not assume the last element is newest.
func newestAttempt(times []time.Time) time.Time {
	max := times[0]
	for _, t := range times[1:] {
		if t.After(max) {
			max = t
		}
	}
	return max
}
