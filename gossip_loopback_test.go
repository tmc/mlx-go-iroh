package irohmesh_test

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/netaddr"
	irohmesh "github.com/tmc/mlx-go-iroh"
)

// TestSignedGossipLoopback subscribes two endpoints to one topic and confirms a
// signed envelope published by one is received and verified by the other —
// exercising Subscribe + PublishSigned + VerifiedEnvelopes end to end.
func TestSignedGossipLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "irohmesh/test/gossip/1"
	var topic gossip.TopicID
	copy(topic[:], "irohmesh-test-topic")

	srvKey, _ := irohmesh.GenerateNodeKey()
	server, err := irohmesh.Bind(ctx, irohmesh.Config{BindAddr: "127.0.0.1:0", Identity: srvKey.Ed25519()})
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	defer server.Close()
	serverTopic, err := server.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	defer serverTopic.Close()
	noop := func(context.Context, *irohmesh.Conn) error { return nil }
	if err := server.Serve(alpn, noop, nil); err != nil {
		t.Fatalf("server serve: %v", err)
	}

	clientKey, _ := irohmesh.GenerateNodeKey()
	client, err := irohmesh.Bind(ctx, irohmesh.Config{BindAddr: "127.0.0.1:0", Identity: clientKey.Ed25519()})
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Close()
	bootstrap := []netaddr.EndpointAddr{server.DialableAddr()}
	clientTopic, err := client.Subscribe(ctx, topic, bootstrap)
	if err != nil {
		t.Fatalf("client subscribe: %v", err)
	}
	defer clientTopic.Close()
	if err := client.Serve(alpn, noop, nil); err != nil {
		t.Fatalf("client serve: %v", err)
	}

	// Wait for the swarm to connect, then publish a signed envelope from the
	// client and expect the server to receive and verify it.
	if err := clientTopic.Joined(ctx); err != nil {
		t.Fatalf("client join: %v", err)
	}

	want := []byte(`{"hello":"mesh"}`)
	go func() {
		// Publish a few times; gossip delivery is eventual after neighbor-up.
		for i := 0; i < 10; i++ {
			_ = irohmesh.PublishSigned(ctx, clientTopic, clientKey, want)
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()

	for env, err := range irohmesh.VerifiedEnvelopes(serverTopic) {
		if err != nil {
			continue
		}
		if string(env.Payload) == string(want) {
			if string(env.NodeID) != string(clientKey.Public()) {
				t.Fatalf("envelope signer = %x, want client %x", env.NodeID, clientKey.Public())
			}
			return // received and verified
		}
		if ctx.Err() != nil {
			break
		}
	}
	t.Fatal("did not receive the signed envelope before timeout")
}
