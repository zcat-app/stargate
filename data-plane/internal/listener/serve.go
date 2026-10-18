// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package listener

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

const maxFramingHandlers = 200

// Serve owns inbound admission. A permit is acquired before Accept and is
// held only through SOCKS framing, so a stalled local client cannot create an
// unbounded handler population and established forwarding does not consume a
// framing slot.
func Serve(ctx context.Context, lis net.Listener, d *Deps) error {
	permits := make(chan struct{}, maxFramingHandlers)
	backoff := 5 * time.Millisecond
	const maxBackoff = time.Second

	for {
		select {
		case <-ctx.Done():
			return nil
		case permits <- struct{}{}:
		}

		if ctx.Err() != nil {
			<-permits
			return nil
		}

		conn, err := lis.Accept()
		if err != nil {
			<-permits
			if ctx.Err() != nil {
				return nil
			}
			var timeoutErr interface{ Timeout() bool }
			var temporaryErr interface{ Temporary() bool }
			if (errors.As(err, &timeoutErr) && timeoutErr.Timeout()) ||
				(errors.As(err, &temporaryErr) && temporaryErr.Temporary()) {
				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				continue
			}
			return err
		}

		if ctx.Err() != nil {
			_ = conn.Close()
			<-permits
			return nil
		}
		backoff = 5 * time.Millisecond

		var releaseOnce sync.Once
		release := func() {
			releaseOnce.Do(func() { <-permits })
		}
		go func() {
			defer release()
			handleConn(conn, d, release)
		}()
	}
}
