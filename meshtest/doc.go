// SPDX-License-Identifier: MIT

// Package meshtest provides test helpers for irohmesh-based meshes: reserving a
// loopback address to bind, and deriving a deterministic identity from a seed
// byte so a test's EndpointID is reproducible.
//
// It is a separate package so importing it never pulls the testing package into
// the irohmesh root import graph. Helpers that take a *testing.T call t.Helper
// and t.Fatal, so a failure is reported at the caller.
package meshtest
