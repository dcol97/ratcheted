// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package dv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

var blockchain = NewBlockchainARCAD(hybrid)

func TestBlockchainARCAD_Alternating(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := blockchain.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := blockchain.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := blockchain.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))

		ct, err = blockchain.Send(bob, ad, pt)
		require.Nil(err)

		pt, err = blockchain.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestBlockchainARCAD_Unidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := blockchain.Init()
	require.Nil(err)

	for i := 0; i < 10; i++ {
		ct, err := blockchain.Send(alice, ad, msg)
		require.Nil(err)

		pt, err := blockchain.Receive(bob, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		ct, err := blockchain.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := blockchain.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}

func TestBlockchainARCAD_DefUnidirectional(t *testing.T) {
	require := require.New(t)

	msg := []byte("arcad")
	ad := []byte("ad")

	alice, bob, err := blockchain.Init()
	require.Nil(err)

	var cts [10][]byte
	for i := 0; i < 10; i++ {
		ct, err := blockchain.Send(alice, ad, msg)
		require.Nil(err)

		cts[i] = ct
	}

	for i := 0; i < 10; i++ {
		ct, err := blockchain.Send(bob, ad, msg)
		require.Nil(err)

		pt, err := blockchain.Receive(alice, ad, ct)
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}

	for i := 0; i < 10; i++ {
		pt, err := blockchain.Receive(bob, ad, cts[i])
		require.Nil(err)
		require.True(bytes.Equal(msg, pt))
	}
}
