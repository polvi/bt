package bttest

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/polvi/bt"
	"net"
	"os"
)

func NewPeer(meta *bt.MetaInfo) *bt.Peer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("bttest: failed to listen on a port: %v", err))
		}
	}
	p := &bt.Peer{PeerAddr: l.Addr().String(), Listener: l}
	id := make([]byte, 20)
	_, err = rand.Read(id)
	if err != nil {
		panic(fmt.Sprintf("failed to get peerid: %v", err))
	}
	i := fmt.Sprintf("%x", id)
	p.PeerId = i[:20]
	p.MetaInfo = meta

	f_out, err := os.Create("dat2.bz2")
	if err != nil {
		panic(fmt.Sprintf("bttest: failed to create backing file: %v", err))
	}
	p.File = f_out
	p.Bitfield = bt.NewBitset(meta.NumPieces)
	go p.Serve(p.Listener)
	return p
}
func NewPeerWithData(meta *bt.MetaInfo, filename string) (*bt.Peer, error) {
	p := NewPeer(meta)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	p.File = f
	for i := 0; i < meta.NumPieces; i++ {
		p.Bitfield.Set(i)
	}
	return p, nil
}

type ResponseRecorder struct {
	Body *bytes.Buffer
}

func NewRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		Body: new(bytes.Buffer),
	}
}

func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	if rw.Body != nil {
		rw.Body.Write(buf)
	}
	return len(buf), nil
}
func (rw *ResponseRecorder) Close() error {
	return nil
}
