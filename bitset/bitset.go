package bitset

import (
	"errors"
	"fmt"
)

// As defined by the bittorrent protocol, this bitset is big-endian, such that
// the high bit of the first byte is block 0

type Bitset struct {
	b         []byte
	n         int
	endIndex  int
	endOffset int
	// TODO: remove endmask
	endMask byte // Which bits of the last byte are valid
}

func (b *Bitset) String() string {
	s := ""
	for i := 0; i < b.n; i++ {
		if b.IsSet(i) {
			s += "1"
		} else {
			s += "0"
		}
	}
	return s
}

func NewBitset(n int) *Bitset {
	endIndex, endOffset := n>>3, n&7
	endMask := ^byte(255 >> byte(endOffset))
	if endOffset == 0 {
		endIndex = -1
		endOffset = 8
	}
	return &Bitset{make([]byte, (n+7)>>3), n, endIndex, endOffset, endMask}
}

// Creates a new bitset from a given byte stream. Returns nil if the
// data is invalid in some way.
func NewBitsetFromBytes(n int, data []byte) (*Bitset, error) {
	bitset := NewBitset(n)
	if len(bitset.b) != len(data) {
		return nil, errors.New(fmt.Sprintf("expected %d pieces, got %d ", len(bitset.b), len(data)))
	}
	copy(bitset.b, data)
	if bitset.endIndex >= 0 && bitset.b[bitset.endIndex]&(^bitset.endMask) != 0 {
		return nil, errors.New("bitfield out of range")
	}
	return bitset, nil
}

func (b *Bitset) Set(index int) {
	b.checkRange(index)
	b.b[index>>3] |= byte(128 >> byte(index&7))
}

func (b *Bitset) Clear(index int) {
	b.checkRange(index)
	b.b[index>>3] &= ^byte(128 >> byte(index&7))
}

func (b *Bitset) IsSet(index int) bool {
	return (b.b[index>>3] & byte(128>>byte(index&7))) != 0
}

func (b *Bitset) Len() int {
	return b.n
}

func (b *Bitset) InRange(index int) bool {
	return 0 <= index && index <= b.lastVaildBit()
}

func (b *Bitset) checkRange(index int) {
	if !b.InRange(index) {
		panic(fmt.Sprintf("Index %d out of range 0..%d.", index, b.n))
	}
}

func (b *Bitset) AndNot(b2 *Bitset) {
	if b.n != b2.n {
		panic(fmt.Sprintf("Unequal bitset sizes %d != %d", b.n, b2.n))
	}
	for i := 0; i <= b.lastVaildBit(); i++ {
		b.b[i] = b.b[i] & ^b2.b[i]
	}
}

func (b *Bitset) IsEndValid() bool {
	if b.endIndex >= 0 {
		return (b.b[b.endIndex] & b.endMask) == 0
	}
	return true
}

// TODO: Make this fast
func (b *Bitset) FindNextSet(index int) int {
	for i := index; i <= b.lastVaildBit(); i++ {
		if (b.b[i>>3] & byte(128>>byte(i&7))) != 0 {
			return i
		}
	}
	return -1
}

// TODO: Make this fast
func (b *Bitset) FindNextClear(index int) int {
	for i := index; i <= b.lastVaildBit(); i++ {
		if (b.b[i>>3] & byte(128>>byte(i&7))) == 0 {
			return i
		}
	}
	return -1
}

func (b *Bitset) Bytes() []byte {
	return b.b
}

// TODO: make this faster? cache the result?
func (b *Bitset) lastVaildBit() int {
	return (len(b.b)-1)*8 + b.endOffset - 1
}
