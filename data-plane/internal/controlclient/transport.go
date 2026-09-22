// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package controlclient

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
)

// NewTransportCredentials applies wire-auth §2.4's lifetime to both IPC roles.
func NewTransportCredentials(cfg *tls.Config) credentials.TransportCredentials {
	return transportCredentials(cfg, 60*time.Second)
}

func transportCredentials(cfg *tls.Config, lifetime time.Duration) credentials.TransportCredentials {
	return &boundedCredentials{TransportCredentials: credentials.NewTLS(cfg), lifetime: lifetime}
}

type boundedCredentials struct {
	credentials.TransportCredentials
	lifetime time.Duration
}

func (c *boundedCredentials) Clone() credentials.TransportCredentials {
	return &boundedCredentials{TransportCredentials: c.TransportCredentials.Clone(), lifetime: c.lifetime}
}

func (c *boundedCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if err != nil {
		return nil, nil, err
	}
	return expireTransport(conn, raw, c.lifetime), info, nil
}

func (c *boundedCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ServerHandshake(raw)
	if err != nil {
		return nil, nil, err
	}
	return expireTransport(conn, raw, c.lifetime), info, nil
}

type expiringConn struct {
	net.Conn
	raw   net.Conn
	timer *time.Timer
}

func expireTransport(conn, raw net.Conn, lifetime time.Duration) net.Conn {
	// Close the socket, not TLS Close: a hostile peer must not extend the
	// deadline by withholding reads of close_notify (wire-auth §2.4).
	return &expiringConn{Conn: conn, raw: raw, timer: time.AfterFunc(lifetime, func() { _ = raw.Close() })}
}

func (c *expiringConn) Close() error {
	c.timer.Stop()
	_ = c.raw.Close()
	return c.Conn.Close()
}
