// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package kukem

import (
	"crypto/rand"
	"crypto/sha256"
	//	"encoding/binary"
	"fmt"
	"math/big"
	//	"github.com/bwesterb/go-ristretto"
	"github.com/qantik/ratcheted/primitives"
)

// Uses code from https://github.com/stefanomozart/paillier/blob/master/paillier.go as a base

var zero = new(big.Int).SetInt64(0)
var one = new(big.Int).SetInt64(1)
var digbits = 256

// LinearDK designates a Linear DK protocol instance.
type LinearDK struct {
	Bitlen int
}

// linearDKParams composes the public parameters of a protocol instance.
// Base point (generator of prime order (sub)group) is implicit
type linearDKParams struct {
	T   uint32
	N   *big.Int
	G   *big.Int
	N2  *big.Int
	NN4 *big.Int // N^2 / 4
	A0s []*big.Int
	A1s []*big.Int
}

type linearDKCiphertext struct {
	ct *big.Int
}

// Can be EK and possibly DK at a given point
type linearDKEntity struct {
	Lambda *big.Int
	Mu     *big.Int

	DKs    []*big.Int
	AD_DK  []byte
	Ind_DK uint32
	CT_DK  []byte

	EK     *big.Int
	AD_EK  []byte
	Ind_EK uint32
	CT_EK  []byte
}

// NewLinearDK creates a fresh protocol instance
func NewLinearDK(bitlen int) *LinearDK {
	return &LinearDK{Bitlen: bitlen}
}

// Hash functions
// K = {1, ..., floor(N^2/4)}
// H_1 : G_QR -> G_QR
// H_2: K x G_QR x {0, 1}^{*} -> K
// H_3 : G_QR -> {0, 1}^{256}
// TODO: Use different prefixes for each H_i (important for practice)

/*
// We compute H(s) then set output to
// H(s) || H(H(s)) || ... || H...H(s)
func HashOneLDK(s []byte) ([]byte, error) {
	if len(s)%32 != 0 {
		return nil, nil
	}
	num := bitlen / 256
	dig := make([]byte, 0, bitlen)
	h := sha256.New()
	h.Write(s)
	a := h.Sum(nil)
	dig = append(dig, a...)
	for i := 0; i < num-1; i++ {
		h := sha256.New()
		h.Write(dig[i*32 : (i+1)*32])
		dig = append(dig, h.Sum(nil)...)
	}
	return dig, nil
}
*/

// As in paper
func HashOneLDK(in *big.Int, a0s, a1s []*big.Int, nn *big.Int) (*big.Int, error) {
	s := in.Bytes()
	h := sha256.New()
	h.Write(s)
	_ = h.Sum(nil)
	prod := new(big.Int).Set(one)
	masks := []byte{1, 2, 4, 8, 16, 32, 64, 128}
	for i := 0; i < digbits/8; i++ {
		for j := 0; j < 8; j++ {
			bit := int(s[i] & masks[j] >> uint32(j))
			if bit == 0 {
				prod.Mod(new(big.Int).Mul(a0s[8*i+j], prod), nn)
			} else {
				prod.Mod(new(big.Int).Mul(a1s[8*i+j], prod), nn)
			}
		}
	}
	return prod, nil
}

func HashTwoLDK(prevad, ct, ad []byte, bitlen int) ([]byte, error) {
	// Checking that prevad is
	// TODO: check len of ct and prevad
	data := make([]byte, 0, len(prevad)+len(ct)+len(ad))
	data = append(data, prevad...)
	data = append(data, ct...)
	data = append(data, ad...)
	h := sha256.New()
	h.Write(data)
	dig := make([]byte, 0, bitlen*2)
	dig = append(dig, h.Sum(nil)...)
	for i := 1; i < (bitlen*2)/256; i++ {
		h = sha256.New()
		h.Write(dig[(i-1)*32 : i*32])
		dig = append(dig, h.Sum(nil)...)
	}
	return dig, nil
}

func HashThreeLDK(s []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(s)
	return h.Sum(nil), nil
}

// Setup establishes the public parameters and generates a root entity PKG.
// FIXME: Use seed
func (l LinearDK) Setup(seed []byte, t int) (params, initdk []byte, err error) {
	// assuming bitlen is even
	bitlen := l.Bitlen
	var p, pdash, q, qdash *big.Int
	if bitlen == 2048 {
		p, _ = new(big.Int).SetString("147596411006181089386129244352705723616351868461555641239967690199541917786928938400967319212516077644805674702792480696049125599442468141400782112016559658245332768498550968132920968132090721734509322395697947774030189769533590563128658868660446084145054384791000178390013732899249554550292976624918572134099", 10)
		pdash, _ = new(big.Int).SetString("73798205503090544693064622176352861808175934230777820619983845099770958893464469200483659606258038822402837351396240348024562799721234070700391056008279829122666384249275484066460484066045360867254661197848973887015094884766795281564329434330223042072527192395500089195006866449624777275146488312459286067049", 10)
		q, _ = new(big.Int).SetString("170918028960163089123473236661726015758889461308697600215662369039181191572798825592552076697249849215853222677847855731589185352122636329701967886923309293908736899202853958166323267094701291915319388325415022596114812824512664598677400118945105672662576344050510534043516802409721724311305071589674500818499", 10)
		qdash, _ = new(big.Int).SetString("85459014480081544561736618330863007879444730654348800107831184519590595786399412796276038348624924607926611338923927865794592676061318164850983943461654646954368449601426979083161633547350645957659694162707511298057406412256332299338700059472552836331288172025255267021758401204860862155652535794837250409249", 10)
	} else {
		p, pdash = getSafePrime(bitlen/2 - 1)
		q, qdash = getSafePrime(bitlen/2 - 1)
	}
	pdashqdash := new(big.Int).Mul(pdash, qdash)

	n := new(big.Int).Mul(p, q)
	nn := new(big.Int).Mul(n, n)
	nn4 := new(big.Int).Div(nn, big.NewInt(4))

	lambda := phi(p, q)
	mu := new(big.Int).ModInverse(lambda, n)

	// Sample generator
	// c.f. p315 of ISC 2018 proceedings
	//	g := new(big.Int).Add(n, one)
	var gdash *big.Int
	for {
		gdash, err = rand.Int(rand.Reader, nn)
		if err != nil {
			fmt.Println(err)
			return
		}
		gcd := new(big.Int).GCD(nil, nil, gdash, nn)
		if gcd.Cmp(one) == 0 {
			break
		}
	}
	gdash.Exp(gdash, new(big.Int).Mul(big.NewInt(2), n), nn)
	a, err := rand.Int(rand.Reader, pdashqdash)
	b := new(big.Int).Set(mu)
	// g = g'^a * (1 + N)^b
	g := new(big.Int).Mul(new(big.Int).Exp(gdash, a, nn),
		new(big.Int).Exp(new(big.Int).Add(n, one), b, nn))

	// a terms
	a0s := make([]*big.Int, digbits)
	a1s := make([]*big.Int, digbits)
	noverl := new(big.Int).Div(n, big.NewInt(int64(digbits)))
	for i := 0; i < digbits; i++ {
		coeff, errr := rand.Int(rand.Reader, noverl)
		if errr != nil {
			err = errr
			return
		}
		a0s[i] = new(big.Int).Exp(g, coeff, nn)
	}
	for i := 0; i < digbits; i++ {
		coeff, errr := rand.Int(rand.Reader, noverl)
		if errr != nil {
			err = errr
			return
		}
		a1s[i] = new(big.Int).Exp(g, coeff, nn)
	}

	decapsKeys := make([]*big.Int, t+1)
	encapsKeyExp, err := rand.Int(rand.Reader, n)
	if err != nil {
		return
	}
	encapsKey := new(big.Int).Exp(g, encapsKeyExp, nn)

	decapsKeys[0] = SolvePDL(encapsKey, n, nn, lambda)
	newTempEk := new(big.Int).Set(encapsKey)
	for i := 1; i <= t; i++ {
		newTempEk, _ := HashOneLDK(newTempEk, a0s, a1s, nn)
		gcd := new(big.Int).GCD(nil, nil, newTempEk, n)
		// Check if quadratic residue
		// Also have vector [b_1, ..., b_t] that says whether to square or not?
		if gcd.Cmp(one) != 0 {
			fmt.Println("gcd not 1", gcd)
			// TODO: Hash last 32 bytes if not in Z_N*
		}
		decapsKeys[i] = SolvePDL(newTempEk, n, nn, lambda)
	}

	ps := &linearDKParams{
		T:   uint32(t),
		N:   n,
		G:   g,
		N2:  nn,
		NN4: nn4,
		A0s: a0s,
		A1s: a1s,
	}
	params, err = ps.GobEncode()
	if err != nil {
		return
	}

	r := &linearDKEntity{
		Lambda: lambda,
		Mu:     mu,
		DKs:    decapsKeys,
		AD_DK:  []byte{},
		Ind_DK: uint32(0),
		CT_DK:  []byte{},

		EK:     encapsKey,
		AD_EK:  []byte{},
		Ind_EK: uint32(0),
		CT_EK:  []byte{},
	}

	initdk, err = r.GobEncode()
	return
}

func (l LinearDK) UpdateEK(params, ek, ad []byte) (newek []byte, err error) {
	bitlen := l.Bitlen
	var p linearDKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearDKEntity
	if err = e.GobDecode(ek); err != nil {
		return
	}

	if e.Ind_EK >= p.T {
		return
	}

	var inad []byte
	var inct []byte

	if len(e.AD_EK) == 0 {
		inad = make([]byte, bitlen*2)
	} else {
		inad = e.AD_EK
	}

	if len(e.CT_EK) == 0 {
		inct = make([]byte, bitlen*2)
	} else {
		inct = e.CT_EK
	}

	newadek, _ := HashTwoLDK(inad, inct, ad, bitlen)
	e.EK, _ = HashOneLDK(e.EK, p.A0s, p.A1s, p.N2)
	e.AD_EK = newadek
	e.Ind_EK = e.Ind_EK + 1
	e.CT_EK = []byte{}
	newek, err = e.GobEncode()

	return
}

func (l LinearDK) UpdateDK(params, dk, ad []byte) (newdk []byte, err error) {
	bitlen := l.Bitlen
	var p linearDKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearDKEntity
	if err = e.GobDecode(dk); err != nil {
		return
	}

	if e.Ind_DK >= p.T {
		return
	}

	// TODO: remove first DK elt

	var inad []byte
	var inct []byte

	if len(e.AD_DK) == 0 {
		inad = make([]byte, bitlen*2)
	} else {
		inad = e.AD_DK
	}

	if len(e.CT_DK) == 0 {
		inct = make([]byte, bitlen*2)
	} else {
		inct = e.CT_DK
	}

	newaddk, _ := HashTwoLDK(inad, inct, ad, bitlen)
	e.AD_DK = newaddk
	e.Ind_DK = e.Ind_DK + 1
	e.CT_DK = []byte{}
	newdk, err = e.GobEncode()
	return
}

func (l LinearDK) Encaps(params, ek []byte) (newEK []byte, ct []byte, k []byte, err error) {
	var p linearDKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearDKEntity
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

	r, err := rand.Int(rand.Reader, p.NN4)
	ct = new(big.Int).Exp(p.G, r, p.N2).Bytes()
	e.CT_EK = ct
	if len(e.AD_EK) > 0 {
		// multiply r by H_2(ad)
		r.Mul(r, new(big.Int).SetBytes(e.AD_EK))
	}

	yInd := new(big.Int).Exp(e.EK, r, p.N2)
	k, _ = HashThreeLDK(yInd.Bytes())

	newEK, err = e.GobEncode()
	return
}

func (l LinearDK) Decaps(params, dk, ct []byte) (newDK []byte, k []byte, err error) {
	var p linearDKParams
	if err = p.GobDecode(params); err != nil {
		return
	}

	var e linearDKEntity
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

	e.CT_DK = ct
	exp := new(big.Int).Set(e.DKs[e.Ind_DK])
	if len(e.AD_DK) > 0 {
		// multiply exp by H_2(ad)
		exp.Mul(exp, new(big.Int).SetBytes(e.AD_DK))
	}

	ctInt := new(big.Int).SetBytes(ct)
	yInd := new(big.Int).Exp(ctInt, exp, p.N2)
	k, _ = HashThreeLDK(yInd.Bytes())

	newDK, err = e.GobEncode()
	return
}

type linearDKEntityPacket struct {
	Lambda []byte
	Mu     []byte

	DKs    [][]byte
	AD_DK  []byte
	Ind_DK uint32
	CT_DK  []byte

	EK     []byte
	AD_EK  []byte
	Ind_EK uint32
	CT_EK  []byte
}

func (e linearDKEntity) GobEncode() ([]byte, error) {
	packet := &linearDKEntityPacket{
		Lambda: e.Lambda.Bytes(),
		Mu:     e.Mu.Bytes(),

		AD_DK:  e.AD_DK,
		Ind_DK: e.Ind_DK,
		CT_DK:  e.CT_DK,

		EK:     e.EK.Bytes(),
		AD_EK:  e.AD_EK,
		Ind_EK: e.Ind_EK,
		CT_EK:  e.CT_EK,
	}
	for _, dk := range e.DKs {
		packet.DKs = append(packet.DKs, dk.Bytes())
	}
	return primitives.Encode(&packet)
}

func (e *linearDKEntity) GobDecode(data []byte) error {
	var packet linearDKEntityPacket
	if err := primitives.Decode(data, &packet); err != nil {
		return err
	}

	e.Lambda = new(big.Int).SetBytes(packet.Lambda)
	e.Mu = new(big.Int).SetBytes(packet.Mu)

	e.EK = new(big.Int).SetBytes(packet.EK)
	e.AD_DK = packet.AD_DK
	e.Ind_DK = packet.Ind_DK
	e.CT_DK = packet.CT_DK

	for _, dk := range packet.DKs {
		e.DKs = append(e.DKs, new(big.Int).SetBytes(dk))
	}
	e.AD_EK = packet.AD_EK
	e.Ind_EK = packet.Ind_EK
	e.CT_EK = packet.CT_EK

	return nil
}

type linearDKParamsPacket struct {
	T   uint32
	N   []byte
	G   []byte
	N2  []byte
	NN4 []byte
	A0s [][]byte
	A1s [][]byte
}

func (p linearDKParams) GobEncode() ([]byte, error) {
	a0s := make([][]byte, digbits)
	a1s := make([][]byte, digbits)
	for i := 0; i < digbits; i++ {
		a0s[i] = p.A0s[i].Bytes()
	}
	for i := 0; i < digbits; i++ {
		a1s[i] = p.A1s[i].Bytes()
	}
	packet := &linearDKParamsPacket{
		T:   p.T,
		N:   p.N.Bytes(),
		G:   p.G.Bytes(),
		N2:  p.N2.Bytes(),
		NN4: p.NN4.Bytes(),
		A0s: a0s,
		A1s: a1s,
	}
	return primitives.Encode(&packet)
}

func (p *linearDKParams) GobDecode(data []byte) error {
	var packet linearDKParamsPacket
	if err := primitives.Decode(data, &packet); err != nil {
		return err
	}

	p.T = packet.T
	p.N = new(big.Int).SetBytes(packet.N)
	p.G = new(big.Int).SetBytes(packet.G)
	p.N2 = new(big.Int).SetBytes(packet.N2)
	p.NN4 = new(big.Int).SetBytes(packet.NN4)
	p.A0s = make([]*big.Int, digbits)
	p.A1s = make([]*big.Int, digbits)
	for i := 0; i < digbits; i++ {
		p.A0s[i] = new(big.Int).SetBytes(packet.A0s[i])
	}
	for i := 0; i < digbits; i++ {
		p.A1s[i] = new(big.Int).SetBytes(packet.A1s[i])
	}

	return nil
}

func SolvePDL(c, n, nn, lambda *big.Int) *big.Int {
	C := new(big.Int).Exp(c, lambda, nn)
	return L(C, n)
}

// L (x,n) = (x-1)/n is the largest integer quocient `q` to satisfy (x-1) >= q*n
func L(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

// generates a random number, testing if it is a probable prime
// generates safe primes
func getSafePrime(bits int) (*big.Int, *big.Int) {
	count := 0
	for {
		count++
		pdash, err := rand.Prime(rand.Reader, bits)
		p := new(big.Int).Add(new(big.Int).Mul(pdash, big.NewInt(2)), one)
		if !p.ProbablyPrime(20) {
			continue
		}
		if err != nil {
			panic("Error while reading crypto/rand")
		}

		return p, pdash
	}
}

// getRandom generates a random Int `r` such that `r < n` and `gcd(r,n) = 1`
func getRandom(n *big.Int) *big.Int {
	gcd := new(big.Int)
	r := new(big.Int)
	err := fmt.Errorf("")

	for gcd.Cmp(one) != 0 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			panic("Error while reading crypto/rand")
		}

		gcd = new(big.Int).GCD(nil, nil, r, n)
	}
	return r
}

// Computes Carmichael's function on `n`, `λ(n) = lcm(p-1, q-1)`
// as |(p - 1)*(q - 1)|/GCD(p - 1,q - 1)
func lambda(p *big.Int, q *big.Int) *big.Int {
	pminone := new(big.Int).Sub(p, one)
	qminone := new(big.Int).Sub(q, one)
	l := new(big.Int).GCD(nil, nil, pminone, qminone)
	return l.Mul(l.Div(pminone, l), qminone)
}

// Computes Euler's totient function `φ(p,q) = (p-1)*(q-1)`
func phi(x, y *big.Int) *big.Int {
	p1 := new(big.Int).Sub(x, one)
	q1 := new(big.Int).Sub(y, one)
	return new(big.Int).Mul(p1, q1)
}

// generator tests smalls primes for gcd(L(g^λ mod n^2), n) = 1.
// If no prime smaller then 17 holds that condition, returns n+1
func generator(n, nn, lambda *big.Int) (*big.Int, *big.Int) {
	primes := []int64{2, 3, 5, 7, 11, 13, 17}
	for _, p := range primes {
		g := new(big.Int).SetInt64(p)
		z := new(big.Int).Exp(g, lambda, nn)
		mu := L(z, n)
		if z.GCD(nil, nil, mu, n).Cmp(one) == 0 {
			return g, mu.ModInverse(mu, n)
		}
	}
	return new(big.Int).Add(n, one), new(big.Int).ModInverse(n, nn)
}
