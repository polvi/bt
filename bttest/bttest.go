package bttest

import (
	"bufio"
	"bytes"
	"github.com/polvi/bt"
	"io"
	"os"
)

func NewPeerWithData(meta *bt.MetaInfo, filename string) (*bt.Peer, error) {
	p := bt.NewPeer(meta)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	p.File = f
	for i := 0; i < meta.NumPieces; i++ {
		p.Bitfield.Set(i)
	}
	buf := bufio.NewReaderSize(f, int(p.MetaInfo.Info.PieceLength))
	io.Copy(p.Chunker, buf)
	return p, nil
}
func NewPeerWithDataPieces(meta *bt.MetaInfo, filename string, pieces int, piece_off int) (*bt.Peer, error) {
	p := bt.NewPeer(meta)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	p.File = f
	for i := piece_off; i < piece_off+pieces; i++ {
		p.Bitfield.Set(i)
	}
	f.Seek(p.MetaInfo.Info.PieceLength*int64(piece_off), 0)
	buf := bufio.NewReaderSize(f, int(p.MetaInfo.Info.PieceLength))
	io.Copy(p.Chunker, buf)
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
