package bitset

import "testing"

func TestLastVaildBit(t *testing.T) {
	for i := 0; i < 1024; i++ {
		bitset := NewBitset(i)
		if bitset.lastVaildBit() != i-1 {
			t.Errorf("#%d: lastVaildBit = %d, want %d", bitset.lastVaildBit(), i-1)
		}
	}
}
