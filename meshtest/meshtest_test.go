package meshtest_test

import (
	"testing"

	"github.com/tmc/mlx-go-iroh/meshtest"
)

func TestReserveLoopbackAddrIsLoopbackAndFresh(t *testing.T) {
	a := meshtest.ReserveLoopbackAddr(t)
	if !a.Addr().IsLoopback() {
		t.Fatalf("address %v is not loopback", a)
	}
	if a.Port() == 0 {
		t.Fatal("reserved a zero port")
	}
	// Two reservations should not collide on the same port in practice.
	if b := meshtest.ReserveLoopbackAddr(t); a.Port() == b.Port() {
		t.Fatalf("two reservations returned the same port %d", a.Port())
	}
}

func TestDeterministicSecretIsStableAndDistinct(t *testing.T) {
	sk1, id1 := meshtest.DeterministicSecret(0x01)
	sk1again, id1again := meshtest.DeterministicSecret(0x01)
	if id1 != id1again {
		t.Fatalf("same fill gave different ids: %v != %v", id1, id1again)
	}
	if sk1.Bytes() != sk1again.Bytes() {
		t.Fatal("same fill gave different secret keys")
	}
	if _, id2 := meshtest.DeterministicSecret(0x02); id1 == id2 {
		t.Fatal("distinct fills gave the same id")
	}
	if id1.IsZero() {
		t.Fatal("derived a zero endpoint id")
	}
}
