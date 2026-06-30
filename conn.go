package irohmesh

import (
	"context"
	"net"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// Conn is one accepted or dialed connection. It exposes the stream operations a
// protocol needs as [net.Conn] streams, so go-iroh stays fenced inside this
// package and callers run their protocol over a plain io.ReadWriteCloser.
type Conn struct {
	conn *iroh.Conn
}

// RemoteID returns the verified endpoint id of the peer, used to attribute the
// connection to a known node.
func (c *Conn) RemoteID() key.EndpointID { return c.conn.RemoteID() }

// OpenStream opens a bidirectional stream as a [net.Conn]. The connector side
// opens; the listener side accepts the matching stream with [Conn.AcceptStream].
func (c *Conn) OpenStream(ctx context.Context) (net.Conn, error) {
	return c.conn.OpenStreamConn(ctx)
}

// AcceptStream accepts the peer's next bidirectional stream as a [net.Conn].
func (c *Conn) AcceptStream(ctx context.Context) (net.Conn, error) {
	return c.conn.AcceptStreamConn(ctx)
}

// Close releases the connection and its streams.
func (c *Conn) Close() error { return c.conn.Close() }
