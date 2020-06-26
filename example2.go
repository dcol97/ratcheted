package main

import (
	"crypto/elliptic"
	"fmt"

	"github.com/qantik/ratcheted/dv"
	"github.com/qantik/ratcheted/primitives/encryption"
	"github.com/qantik/ratcheted/primitives/hibe"
	"github.com/qantik/ratcheted/primitives/signature"
	"ratcheted/primitives/kukem"
)

var (
	curve = elliptic.P256()
	ecies = encryption.NewECIES(curve)
	ecdsa = signature.NewECDSA(curve)
	aes   = encryption.NewAES()
	gcm   = encryption.NewGCM()

	flag = 100
)

func old() {
	arcad := dv.NewHybridARCAD(ecdsa, ecies, aes, gcm, flag)
	block := dv.NewBlockchainARCAD(arcad)

	msg := []byte("ratchet")
	ad := []byte("ad")

	alice, bob, _ := block.Init()

	c, _ := block.Send(alice, ad, msg)
	r, _ := block.Receive(bob, ad, c)

	fmt.Printf("Sent:\t\t%s\n", msg)
	fmt.Printf("Received:\t%s\n", r)
}

func play_linearek() {
	inst := kukem.NewLinearEK()
	params, initdk, err := inst.Setup(nil, 5)
	newEK, ct, k, err := inst.Encaps(params, initdk)
	//	fmt.Println("NewEK", newEK, len(newEK))
	//	fmt.Println("ct", ct, len(ct))
	//	fmt.Println("k", k, len(k))
	newDK, k, err := inst.Decaps(params, initdk, ct)
	//	fmt.Println("newDK", newDK)
	//	fmt.Println("k", k)
	ad := []byte{0, 1, 2, 3}
	newek, err := inst.UpdateEK(params, newEK, ad)
	newdk, err := inst.UpdateDK(params, newDK, ad)
	newerEK, ct, k, err := inst.Encaps(params, newek)
	fmt.Println("NewerEK", newerEK, len(newerEK))
	fmt.Println("ct", ct, len(ct))
	fmt.Println("k", k, len(k))
	newerDK, k, err := inst.Decaps(params, newdk, ct)
	fmt.Println("newerDK", newerDK)
	fmt.Println("k", k)

	fmt.Println(err)
}

func play_lineardk() {
	inst := kukem.NewLinearDK(2048)
	params, initdk, err := inst.Setup(nil, 5)
	newEK, ct, k, err := inst.Encaps(params, initdk)
	//	fmt.Println("NewEK", newEK, len(newEK))
	//	fmt.Println("ct", ct, len(ct))
	fmt.Println("k", k, len(k))
	newDK, k, err := inst.Decaps(params, initdk, ct)
	//	fmt.Println("newDK", newDK)
	fmt.Println("k", k)

	fmt.Println(err)
	fmt.Println(newEK, newDK)
	ad := []byte{0, 1, 2, 3}
	newek, err := inst.UpdateEK(params, newEK, ad)
	newdk, err := inst.UpdateDK(params, newDK, ad)
	newerEK, ct, k, err := inst.Encaps(params, newek)
	fmt.Println("NewerEK", newerEK, len(newerEK))
	fmt.Println("ct", ct, len(ct))
	fmt.Println("k", k, len(k))
	newerDK, k, err := inst.Decaps(params, newdk, ct)
	fmt.Println("newerDK", newerDK)
	fmt.Println("k", k)
}

func play_gentry() {
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
	dec, _ := inst.Decrypt(ent, c1, c2)
	fmt.Println(msg)
	fmt.Println(dec)
}

func main() {
	//	play_linearek()
	// play_lineardk()
	play_gentry()
}
