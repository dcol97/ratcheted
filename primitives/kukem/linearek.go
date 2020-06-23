// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package kukem

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/bwesterb/go-ristretto"
	"github.com/qantik/ratcheted/primitives"
)

// LinearEK designates a Linear EK protocol instance.
type LinearEK struct{}

// linearEKParams composes the public parameters of a protocol instance.
// Base point (generator of prime order (sub)group) is implicit
type linearEKParams struct {
	T uint32
}

// Can be EK and possibly DK at a given point
type linearEKEntity struct {
	DK     ristretto.Scalar
	AD_DK  []byte
	Ind_DK uint32
	CT_DK  []byte

	EKs    []ristretto.Point
	AD_EK  []byte
	Ind_EK uint32
	CT_EK  []byte
}

// NewLinearEK creates a fresh protocol instance
func NewLinearEK() *LinearEK {
	return &LinearEK{}
}

// Hash functions
// EC is of order ph, where h is ignored due to ristretto
// H_1 : Z_p* -> Z_p*
// H_2: Z_p* x G x {0, 1}^{*} -> Z_p*
// H_3 : G -> {0, 1}^{256}
// TODO: Use different prefixes for each H_i (important for practice)

func HashOneLEK(s []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil), nil
}

func HashTwoLEK(prevad, ct, ad []byte) ([]byte, error) {
	// Checking that prevad, ct are 32 bytes long
	if len(prevad) != 32 || len(ct) != 32 {
		fmt.Println("nil here")
		return nil, nil
	}
	data := make([]byte, 0, len(prevad)+len(ct)+len(ad))
	data = append(data, prevad...)
	data = append(data, ct...)
	data = append(data, ad...)
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil), nil
}

func HashThreeLEK(s []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil), nil
}

// Setup establishes the public parameters and generates a root entity PKG.
// FIXME: Use seed
func (l LinearEK) Setup(seed []byte, t int) (params, initdk []byte, err error) {
	var decapsKey ristretto.Scalar
	encapsKey := make([]ristretto.Point, t+1)

	decapsKey.Rand()
	encapsKey[0].ScalarMultBase(&decapsKey)
	var tempDecapsKey ristretto.Scalar
	tempDecapsKey.Set(&decapsKey)
	for i := 1; i <= t; i++ {
		newTempDkBytes, _ := HashOneLEK(tempDecapsKey.Bytes())
		tempDecapsKey.Derive(newTempDkBytes)
		encapsKey[i].ScalarMultBase(&tempDecapsKey)
	}

	p := &linearEKParams{T: uint32(t)}
	params, err = p.GobEncode()
	if err != nil {
		return
	}

	r := &linearEKEntity{
		DK:     decapsKey,
		AD_DK:  []byte{},
		Ind_DK: uint32(0),
		CT_DK:  []byte{},

		EKs:    encapsKey,
		AD_EK:  []byte{},
		Ind_EK: uint32(0),
		CT_EK:  []byte{},
	}

	initdk, err = r.GobEncode()
	return
}

func (l LinearEK) UpdateEK(params, ek, ad []byte) (newek []byte, err error) {
	var p linearEKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearEKEntity
	if err = e.GobDecode(ek); err != nil {
		return
	}

	if e.Ind_EK >= p.T {
		return
	}

	// TODO: remove first EK elt

	var inad []byte
	var inct []byte

	if len(e.AD_EK) == 0 {
		inad = make([]byte, 32)
	} else {
		inad = e.AD_EK
	}

	if len(e.CT_EK) == 0 {
		inct = make([]byte, 32)
	} else {
		inct = e.CT_EK
	}

	newadek, _ := HashTwoLEK(inad, inct, ad)
	e.AD_EK = newadek
	e.Ind_EK = e.Ind_EK + 1
	e.CT_EK = []byte{}
	newek, err = e.GobEncode()

	return
}

func (l LinearEK) UpdateDK(params, dk, ad []byte) (newdk []byte, err error) {
	var p linearEKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearEKEntity
	if err = e.GobDecode(dk); err != nil {
		return
	}

	if e.Ind_DK >= p.T {
		return
	}

	var dkvar ristretto.Scalar
	newTempDkBytes, _ := HashOneLEK(e.DK.Bytes())
	dkvar.Derive(newTempDkBytes)
	e.DK.Set(&dkvar)

	var inad []byte
	var inct []byte

	if len(e.AD_DK) == 0 {
		inad = make([]byte, 32)
	} else {
		inad = e.AD_DK
	}

	if len(e.CT_DK) == 0 {
		inct = make([]byte, 32)
	} else {
		inct = e.CT_DK
	}

	newaddk, _ := HashTwoLEK(inad, inct, ad)
	e.AD_DK = newaddk
	e.Ind_DK = e.Ind_DK + 1
	e.CT_DK = []byte{}
	newdk, err = e.GobEncode()
	return
}

func (l LinearEK) Encaps(params, ek []byte) (newEK []byte, ct []byte, k []byte, err error) {
	var p linearEKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearEKEntity
	if err = e.GobDecode(ek); err != nil {
		return
	}

	if e.Ind_EK >= p.T {
		return
	}

	// Already encapsulated with respect to current key update
	if len(e.CT_EK) > 0 {
		return
	}

	var rand ristretto.Scalar
	rand.Rand()
	var ctPoint ristretto.Point
	ctPoint.ScalarMultBase(&rand)

	ct = ctPoint.Bytes()
	e.CT_EK = ct

	if len(e.AD_EK) > 0 {
		// multiply rand by H_2(ad)
		var ad ristretto.Scalar
		ad.Derive(e.AD_EK)
		rand.Mul(&ad, &rand)
	}
	var yInd ristretto.Point
	// TODO: if EK elts are removed on update, index is always 0
	yInd.Set(&e.EKs[e.Ind_EK])
	yInd.ScalarMult(&yInd, &rand)
	k, _ = HashThreeLEK(yInd.Bytes())
	newEK, err = e.GobEncode()
	return
}

func (l LinearEK) Decaps(params, dk, ct []byte) (newDK []byte, k []byte, err error) {
	var p linearEKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearEKEntity
	if err = e.GobDecode(dk); err != nil {
		return
	}

	if e.Ind_DK >= p.T {
		return
	}

	// Already decapsulated with respect to current key update
	if len(e.CT_DK) > 0 {
		return
	}

	var exp ristretto.Scalar
	exp.Set(&e.DK)
	if len(e.AD_DK) > 0 {
		var ad ristretto.Scalar
		ad.Derive(e.AD_DK)
		exp.Mul(&ad, &exp)
	}
	var c ristretto.Point
	var tempct [32]byte
	copy(tempct[:], ct)
	c.SetBytes(&tempct)
	c.ScalarMult(&c, &exp)
	k, _ = HashThreeLEK(c.Bytes())

	e.CT_DK = ct
	newDK, err = e.GobEncode()
	return
}

type linearEKEntityPacket struct {
	DK     []byte
	AD_DK  []byte
	Ind_DK uint32
	CT_DK  []byte

	EKs    [][]byte
	AD_EK  []byte
	Ind_EK uint32
	CT_EK  []byte
}

func (e linearEKEntity) GobEncode() ([]byte, error) {
	packet := &linearEKEntityPacket{
		DK:     e.DK.Bytes(),
		AD_DK:  e.AD_DK,
		Ind_DK: e.Ind_DK,
		CT_DK:  e.CT_DK,

		AD_EK:  e.AD_EK,
		Ind_EK: e.Ind_EK,
		CT_EK:  e.CT_EK,
	}
	for _, ek := range e.EKs {
		packet.EKs = append(packet.EKs, ek.Bytes())
	}
	return primitives.Encode(&packet)
}

func (e *linearEKEntity) GobDecode(data []byte) error {
	var packet linearEKEntityPacket
	if err := primitives.Decode(data, &packet); err != nil {
		return err
	}

	var tempdk [32]byte
	copy(tempdk[:], packet.DK)
	e.DK.SetBytes(&tempdk)
	e.AD_DK = packet.AD_DK
	e.Ind_DK = packet.Ind_DK
	e.CT_DK = packet.CT_DK

	for _, ek := range packet.EKs {
		var tmp ristretto.Point
		var tempek [32]byte
		copy(tempek[:], ek)
		tmp.SetBytes(&tempek)
		e.EKs = append(e.EKs, tmp)
	}
	e.AD_EK = packet.AD_EK
	e.Ind_EK = packet.Ind_EK
	e.CT_EK = packet.CT_EK

	return nil
}

func (p linearEKParams) GobEncode() ([]byte, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, p.T)
	return b, nil
}

func (p *linearEKParams) GobDecode(data []byte) error {
	t := binary.LittleEndian.Uint32(data)
	p.T = t
	return nil
}
