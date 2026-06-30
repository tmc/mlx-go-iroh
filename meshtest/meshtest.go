package meshtest

import (
	"net"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/key"
)

// ReserveLoopbackAddr reserves and immediately releases an ephemeral UDP port on
// 127.0.0.1, returning the address so a test can bind or dial a concrete
// host:port without a discovery round trip. The port is free when this returns,
// so a bind racing another process is possible but vanishingly unlikely on
// loopback; it is the standard "pick a free port" pattern for go-iroh tests.
func ReserveLoopbackAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("reserve loopback addr: %v", err)
	}
	addr := c.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := c.Close(); err != nil {
		t.Fatalf("release loopback addr: %v", err)
	}
	return addr
}

// DeterministicSecret derives a go-iroh secret key from a seed filled with one
// byte, returning the key and its EndpointID. The same fill always yields the
// same identity, so a test can assert on a stable EndpointID and give distinct
// nodes distinct, readable seeds (0x01, 0x02, ...). It is for tests only: a
// single-byte seed has no real entropy.
func DeterministicSecret(fill byte) (key.SecretKey, key.EndpointID) {
	var seed [key.SeedSize]byte
	for i := range seed {
		seed[i] = fill
	}
	sk := key.NewSecretKey(seed)
	return sk, sk.Public().EndpointID()
}
