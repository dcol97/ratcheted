// (c) 2018 EPFL
// This code is licensed under MIT license (see LICENSE.txt for details)

package r1

import "testing"

func TestGentry(t *testing.T) {
	pk, sk := gen()

	for i := 0; i < 10; i++ {
		Ka, C := enc(pk)
		Kb := dec(sk, C)
		if !Ka.Equals(Kb) {
			t.Fatal("keys do not match")
		}

		ad := []byte{1, 2, 3}
		pkUpdate(pk, ad)
		skUpdate(sk, ad)
	}
}