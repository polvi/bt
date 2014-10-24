package bt

import (
	"bytes"
	"testing"
)

type fakeConn struct {
	b *bytes.Buffer
}

func (f fakeConn) Read(p []byte) (n int, err error) {
	return f.b.Read(p)
}
func (f fakeConn) Write(p []byte) (n int, err error) {
	return f.b.Write(p)
}

func (f fakeConn) Close() error {
	return nil
}

func BenchmarkReadRequest(b *testing.B) {
	m, _ := PieceMsg(1, 0, []byte{0, 0, 0, 0})
	pc := &PeerConn{
		Conn: fakeConn{b: bytes.NewBuffer(m)},
	}
	for i := 0; i < b.N; i++ {
		ReadRequest(pc)
	}
}
