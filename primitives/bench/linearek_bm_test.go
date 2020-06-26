package main

import (
	"ratcheted/primitives/kukem"
	"testing"
)

func BenchmarkLEKEncaps(b *testing.B) {
	inst := kukem.NewLinearEK()
	params, initdk, _ := inst.Setup(nil, 5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = inst.Encaps(params, initdk)
	}
}

func BenchmarkLEKEncapsAfterUpdate(b *testing.B) {
	inst := kukem.NewLinearEK()
	params, initdk, _ := inst.Setup(nil, 5)
	ad := []byte{0, 1, 2, 3}
	newEK, _, _, _ := inst.Encaps(params, initdk)
	newek, _ := inst.UpdateEK(params, newEK, ad)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = inst.Encaps(params, newek)
	}
}

func BenchmarkLEKDecaps(b *testing.B) {
	inst := kukem.NewLinearEK()
	params, initdk, _ := inst.Setup(nil, 5)
	_, ct, _, _ := inst.Encaps(params, initdk)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = inst.Decaps(params, initdk, ct)
	}
}

func BenchmarkLEKUpdateEK(b *testing.B) {
	inst := kukem.NewLinearEK()
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

func BenchmarkLEKUpdateDK(b *testing.B) {
	inst := kukem.NewLinearEK()
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
