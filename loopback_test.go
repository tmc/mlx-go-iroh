// SPDX-License-Identifier: MIT

package irohmesh_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	irohmesh "github.com/tmc/mlx-go-iroh"
)

// TestEndpointConnectLoopback dials one served endpoint from another over a
// fenced *Conn and exchanges bytes on an application ALPN, confirming the
// substrate brings up an endpoint, serves an app ALPN, and carries a net.Conn
// stream end to end.
func TestEndpointConnectLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const alpn = "irohmesh/test/echo/1"

	srvKey, err := irohmesh.GenerateNodeKey()
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	server, err := irohmesh.Bind(ctx, irohmesh.Config{
		BindAddr: "127.0.0.1:0",
		Identity: srvKey.Ed25519(),
	})
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	defer server.Close()

	// Echo handler: copy the peer's stream back to it, then close the stream.
	// io.Copy returns when the client half-closes its send side; closing the
	// stream (not the connection) flushes the echo and signals EOF, so the
	// client's ReadAll drains cleanly before the connection tears down.
	served := func(ctx context.Context, conn *irohmesh.Conn) error {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		if _, err := io.Copy(s, s); err != nil {
			return err
		}
		return s.Close()
	}
	if err := server.Serve(alpn, served, nil); err != nil {
		t.Fatalf("serve: %v", err)
	}
	ticket := server.LocalTicket()

	client, err := irohmesh.Bind(ctx, irohmesh.Config{BindAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()

	conn, err := client.Connect(ctx, ticket, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	if got, want := conn.RemoteID(), server.ID(); !got.Equal(want) {
		t.Fatalf("remote id = %s, want %s", got, want)
	}

	s, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close the send side so the server's io.Copy sees EOF and echoes.
	if err := s.Close(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo = %q, want %q", got, "hello")
	}
}

// TestServeRejectsDoubleServe confirms Serve is single-shot and validates input.
func TestServeRejectsDoubleServe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ep, err := irohmesh.Bind(ctx, irohmesh.Config{BindAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	defer ep.Close()

	noop := func(context.Context, *irohmesh.Conn) error { return nil }
	if err := ep.Serve("", noop, nil); !errors.Is(err, irohmesh.ErrInvalid) {
		t.Fatalf("serve empty alpn err = %v, want ErrInvalid", err)
	}
	if err := ep.Serve("irohmesh/test/v1", nil, nil); !errors.Is(err, irohmesh.ErrInvalid) {
		t.Fatalf("serve nil handler err = %v, want ErrInvalid", err)
	}
	if err := ep.Serve("irohmesh/test/v1", noop, nil); err != nil {
		t.Fatalf("first serve: %v", err)
	}
	if err := ep.Serve("irohmesh/test/v1", noop, nil); !errors.Is(err, irohmesh.ErrInvalid) {
		t.Fatalf("second serve err = %v, want ErrInvalid", err)
	}
}
