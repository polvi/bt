package chunker

import (
	"fmt"
	"github.com/polvi/bttp/bt"
	"io"
	"os"
	"testing"
)

func TestChunker(t *testing.T) {
	tr, err := bt.NewTorrent("../testData/centos-6.4.img.bz2.torrent")
	if err != nil {
		t.Fatal(err)
	}
	//	tr.MetaInfo.DumpTorrentMetaInfo()
	hashes := tr.MetaInfo.GetPiecesList()
	chunkSize := int(tr.MetaInfo.Info.PieceLength)
	fileSize := int(tr.MetaInfo.Info.Length)
	c, err := NewChunker(hashes, chunkSize, fileSize)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("../testData/centos-6.4.img.bz2")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-c.Done
	}()
	for {
		b := make([]byte, chunkSize)
		n, err := f.Read(b)
		if err == io.EOF {
			fmt.Println("GOT EOF")
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Apply(b[:n])
		if err != nil {
			t.Fatal(err)
		}
	}
}
