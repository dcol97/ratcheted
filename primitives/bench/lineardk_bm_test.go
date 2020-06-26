package main

import (
	"ratcheted/primitives/kukem"
	"testing"
)

func benchmarkLDKSetup(bitlen int, b *testing.B) {
	inst := kukem.NewLinearDK(bitlen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = inst.Setup(nil, 1)
	}
}

//func BenchmarkKUKEMLDKSetup512(b *testing.B)  { benchmarkLDKSetup(512, b) }
//func BenchmarkKUKEMLDKSetup1024(b *testing.B) { benchmarkLDKSetup(1024, b) }
//func BenchmarkKUKEMLDKSetup2048(b *testing.B) { benchmarkLDKSetup(2048, b) }

func BenchmarkLDKEncaps2048(b *testing.B) {
	inst := kukem.NewLinearDK(2048)
	params, initdk, _ := inst.Setup(nil, 5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = inst.Encaps(params, initdk)
	}
}

func BenchmarkLDKDecaps2048(b *testing.B) {
	inst := kukem.NewLinearDK(2048)
	params, initdk, _ := inst.Setup(nil, 5)
	_, ct, _, _ := inst.Encaps(params, initdk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = inst.Decaps(params, initdk, ct)
	}
}

func BenchmarkLDKUpdateEK2048(b *testing.B) {
	inst := kukem.NewLinearDK(2048)
	params, initdk, _ := inst.Setup(nil, 5)
	ad := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	newEK, _, _, _ := inst.Encaps(params, initdk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = inst.UpdateEK(params, newEK, ad)
	}
}

func BenchmarkLDKUpdateDK2048(b *testing.B) {
	inst := kukem.NewLinearDK(2048)
	params, initdk, _ := inst.Setup(nil, 5)
	ad := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	newEK, ct, _, _ := inst.Encaps(params, initdk)
	newDK, _, _ := inst.Decaps(params, newEK, ct)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = inst.UpdateDK(params, newDK, ad)
	}
}
