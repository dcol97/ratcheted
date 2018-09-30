package r2_test

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/qantik/ratcheted/r2"
	"github.com/stretchr/testify/require"
)

var (
	curve        = elliptic.P256()
	ecies        = r2.NewECIES(curve)
	ecdsa        = r2.NewECDSA(curve)
	signcryption = r2.NewSigncryption(ecies, ecdsa)
)

func barkSingle(n int, b *testing.B) {
	require := require.New(b)

	bark := r2.NewBARK(r2.NewUNIARK(signcryption))
	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}
}

func benchmarkBARKSingle(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		barkSingle(i, b)
	}
}

func barkLiteSingle(n int, b *testing.B) {
	require := require.New(b)

	bark := r2.NewBARK(r2.NewLiteUniARCAD())
	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}
	fmt.Println((len(pa) + len(pb)) / 2)
}

func benchmarkBARKLiteSingle(i int, b *testing.B) {
	for n := 0; n < 1; n++ {
		barkLiteSingle(i, b)
	}
}

func barkDual(n int, b *testing.B) {
	require := require.New(b)

	bark := r2.NewBARK(r2.NewUNIARK(signcryption))
	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pbu, ka, ct, err = bark.Send(pbu)
		require.Nil(err)

		pau, kb, err = bark.Receive(pau, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}
}

func benchmarkBARKDual(i int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		barkDual(i, b)
	}
}

func barkLiteDual(n int, b *testing.B) {
	require := require.New(b)

	bark := r2.NewBARK(r2.NewLiteUniARCAD())
	pa, pb, err := bark.Init()
	require.Nil(err)

	for i := 0; i < n/2; i++ {
		pau, ka, ct, err := bark.Send(pa)
		require.Nil(err)

		pbu, kb, err := bark.Receive(pb, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pbu, ka, ct, err = bark.Send(pbu)
		require.Nil(err)

		pau, kb, err = bark.Receive(pau, ct)
		require.Nil(err)
		require.True(bytes.Equal(ka, kb))

		pa, pb = pau, pbu
	}
	fmt.Println((len(pa) + len(pb)) / 2)
}

func benchmarkBARKLiteDual(i int, b *testing.B) {
	for n := 0; n < 1; n++ {
		barkLiteDual(i, b)
	}
}

//func BenchmarkBARKSingle50(b *testing.B)  { benchmarkBARKSingle(50, b) }
//func BenchmarkBARKSingle100(b *testing.B) { benchmarkBARKSingle(100, b) }
//func BenchmarkBARKSingle200(b *testing.B) { benchmarkBARKSingle(200, b) }
//func BenchmarkBARKSingle300(b *testing.B) { benchmarkBARKSingle(300, b) }
//func BenchmarkBARKSingle400(b *testing.B) { benchmarkBARKSingle(400, b) }
//func BenchmarkBARKSingle500(b *testing.B) { benchmarkBARKSingle(500, b) }
//func BenchmarkBARKSingle600(b *testing.B) { benchmarkBARKSingle(600, b) }
//func BenchmarkBARKSingle700(b *testing.B) { benchmarkBARKSingle(700, b) }
//func BenchmarkBARKSingle800(b *testing.B) { benchmarkBARKSingle(800, b) }
//func BenchmarkBARKSingle900(b *testing.B) { benchmarkBARKSingle(900, b) }

func BenchmarkBARKLiteSingle50(b *testing.B)  { benchmarkBARKLiteSingle(50, b) }
func BenchmarkBARKLiteSingle100(b *testing.B) { benchmarkBARKLiteSingle(100, b) }
func BenchmarkBARKLiteSingle200(b *testing.B) { benchmarkBARKLiteSingle(200, b) }
func BenchmarkBARKLiteSingle300(b *testing.B) { benchmarkBARKLiteSingle(300, b) }
func BenchmarkBARKLiteSingle400(b *testing.B) { benchmarkBARKLiteSingle(400, b) }
func BenchmarkBARKLiteSingle500(b *testing.B) { benchmarkBARKLiteSingle(500, b) }
func BenchmarkBARKLiteSingle600(b *testing.B) { benchmarkBARKLiteSingle(600, b) }
func BenchmarkBARKLiteSingle700(b *testing.B) { benchmarkBARKLiteSingle(700, b) }
func BenchmarkBARKLiteSingle800(b *testing.B) { benchmarkBARKLiteSingle(800, b) }
func BenchmarkBARKLiteSingle900(b *testing.B) { benchmarkBARKLiteSingle(900, b) }

//func BenchmarkBARKDual50(b *testing.B)  { benchmarkBARKDual(50, b) }
//func BenchmarkBARKDual100(b *testing.B) { benchmarkBARKDual(100, b) }
//func BenchmarkBARKDual200(b *testing.B) { benchmarkBARKDual(200, b) }
//func BenchmarkBARKDual300(b *testing.B) { benchmarkBARKDual(300, b) }
//func BenchmarkBARKDual400(b *testing.B) { benchmarkBARKDual(400, b) }
//func BenchmarkBARKDual500(b *testing.B) { benchmarkBARKDual(500, b) }
//func BenchmarkBARKDual600(b *testing.B) { benchmarkBARKDual(600, b) }
//func BenchmarkBARKDual700(b *testing.B) { benchmarkBARKDual(700, b) }
//func BenchmarkBARKDual800(b *testing.B) { benchmarkBARKDual(800, b) }
//func BenchmarkBARKDual900(b *testing.B) { benchmarkBARKDual(900, b) }

//func BenchmarkBARKLiteDual50(b *testing.B)  { benchmarkBARKLiteDual(50, b) }
//func BenchmarkBARKLiteDual100(b *testing.B) { benchmarkBARKLiteDual(100, b) }
//func BenchmarkBARKLiteDual200(b *testing.B) { benchmarkBARKLiteDual(200, b) }
//func BenchmarkBARKLiteDual300(b *testing.B) { benchmarkBARKLiteDual(300, b) }
//func BenchmarkBARKLiteDual400(b *testing.B) { benchmarkBARKLiteDual(400, b) }
//func BenchmarkBARKLiteDual500(b *testing.B) { benchmarkBARKLiteDual(500, b) }
//func BenchmarkBARKLiteDual600(b *testing.B) { benchmarkBARKLiteDual(600, b) }
//func BenchmarkBARKLiteDual700(b *testing.B) { benchmarkBARKLiteDual(700, b) }
//func BenchmarkBARKLiteDual800(b *testing.B) { benchmarkBARKLiteDual(800, b) }
//func BenchmarkBARKLiteDual900(b *testing.B) { benchmarkBARKLiteDual(900, b) }