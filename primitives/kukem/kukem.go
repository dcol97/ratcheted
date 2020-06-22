// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

// Package kukem bundles direct implementations of kuKEM schemes under a common interface.
//
// Currently the following schemes are implemented:
//  - Scheme 1 (constant EK, linear DK)
//  - Scheme 2 (linear DK, constant EK)
//
package kukem

// KUKEM specifies a general interface for kuKEM constructions.
type KUKEM interface {
	// Setup creates a new kuKEM instance returning the public parameters and the initial ek/dk
	// Takes t, the max number of key updates, as input and seed
	Setup(seed []byte, t int) (params, initdk []byte, err error)
	// UpdateEK - params, ek, ad -> ek
	UpdateEK(params, ek, ad []byte) ([]byte, error)
	// UpdateDK - params, dk, ad -> dk
	UpdateDK(params, dk, ad []byte) ([]byte, error)
	// Encaps - params, ek -> ek, ct, k
	Encaps(params, ek []byte) ([]byte, []byte, []byte, error)
	// Decaps - params, dk, ct -> dk, k
	Decaps(params, dk, ct []byte) ([]byte, []byte, error)
}
