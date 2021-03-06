package main

import (
	"github.com/qantik/ratcheted/primitives/hibe"
	"testing"
)

func BenchmarkGentryEncryptLevel1(b *testing.B) {
	inst := hibe.NewGentry()
	params, _, _ := inst.Setup(nil)
	msg := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	id := make([][]byte, 0)
	id = append(id, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = inst.Encrypt(params, msg, id)
	}
}

func BenchmarkGentryEncryptLevel10(b *testing.B) {
	inst := hibe.NewGentry()
	params, _, _ := inst.Setup(nil)
	msg := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	id := make([][]byte, 0)
	for i := 0; i < 10; i++ {
		id = append(id, msg)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = inst.Encrypt(params, msg, id)
	}
}

func BenchmarkGentryDecryptLevel1(b *testing.B) {
	inst := hibe.NewGentry()
	params, root, _ := inst.Setup(nil)
	msg := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	id := make([][]byte, 0)
	id = append(id, msg)
	c1, c2, _ := inst.Encrypt(params, msg, id)
	ent, _ := inst.Extract(root, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = inst.Decrypt(ent, c1, c2)
		c := append(c1, c2...)
		_, _ = inst.Extract(ent, c)
	}
}

func BenchmarkGentryDecryptLevel10(b *testing.B) {
	inst := hibe.NewGentry()
	params, root, _ := inst.Setup(nil)
	msg := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	id := make([][]byte, 0)
	for i := 0; i < 10; i++ {
		id = append(id, msg)
	}
	c1, c2, _ := inst.Encrypt(params, msg, id)
	ent, _ := inst.Extract(root, msg)
	for i := 1; i < 10; i++ {
		ent, _ = inst.Extract(ent, msg)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = inst.Decrypt(ent, c1, c2)
		c := append(c1, c2...)
		_, _ = inst.Extract(ent, c)
	}
}

func BenchmarkGentryUpdateDK(b *testing.B) {
	inst := hibe.NewGentry()
	_, root, _ := inst.Setup(nil)
	msg := []byte{
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
		0, 1, 2, 3,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = inst.Extract(root, msg)
	}
}
