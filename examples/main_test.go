package main

import (
	"crypto/sha1"
	"fmt"
	bencode "github.com/jackpal/bencode-go"
	"github.com/polvi/bt"
	"github.com/polvi/bt/bttest"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"testing"
)

func TestChunkStream(t *testing.T) {
	hasher := sha1.New()
	meta, _ := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	p1 := bt.NewPeer(meta, hasher)
	defer p1.Close()
	f, err := os.Open("centos-6.4.img.bz2")
	defer f.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.Seek(5*p1.MetaInfo.Info.PieceLength, 0)
	if _, err := io.Copy(p1.Chunker, f); err != nil {
		t.Fatal(err)
	}
	p1.Chunker.Flush()
	f2, _ := os.Open("centos-6.4.img.bz2")
	defer f2.Close()
	if _, err := io.Copy(p1.Chunker, f2); err != nil {
		t.Fatal(err)
	}
	<-p1.Chunker.DoneNotify()
	if fmt.Sprintf("%x", hasher.Sum(nil)) != "fc76f732918299cd3e5156a02beb3b42e8eb233e" {
		t.Fatal("copied file did not match")
	}

	hasher.Reset()

	// this set tests a full io copy on a file
	p1 = bt.NewPeer(meta, hasher)
	f, err = os.Open("centos-6.4.img.bz2")
	defer f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(p1.Chunker, f); err != nil {
		t.Fatal(err)
	}
	<-p1.Chunker.DoneNotify()
	if fmt.Sprintf("%x", hasher.Sum(nil)) != "fc76f732918299cd3e5156a02beb3b42e8eb233e" {
		t.Fatal("copied file did not match")
	}

}

func TestTripleTorrent(t *testing.T) {
	tracker := bttest.NewTracker()
	defer tracker.Close()
	meta, _ := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	meta.Announce = tracker.URL
	out := ioutil.Discard
	p1 := bt.NewPeer(meta, out)
	defer p1.Close()
	p2 := bt.NewPeer(meta, out)
	defer p2.Close()
	p3, err := bttest.NewPeerWithData(meta, "centos-6.4.img.bz2")
	defer p3.Close()
	wg := new(sync.WaitGroup)
	wg.Add(3)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		p1.Start()
		wg.Done()

	}()
	go func() {
		p2.Start()
		wg.Done()
	}()
	go func() {
		p3.Start()
		wg.Done()
	}()
	f := <-p1.Chunker.DoneNotify()
	hasher := sha1.New()
	io.Copy(hasher, f)
	if fmt.Sprintf("%x", hasher.Sum(nil)) != "fc76f732918299cd3e5156a02beb3b42e8eb233e" {
		t.Fatal("copied file did not match")
	}
	hasher.Reset()
	f = <-p2.Chunker.DoneNotify()
	io.Copy(hasher, f)
	if fmt.Sprintf("%x", hasher.Sum(nil)) != "fc76f732918299cd3e5156a02beb3b42e8eb233e" {
		t.Fatal("copied file did not match")
	}
	hasher.Reset()
	f = <-p3.Chunker.DoneNotify()
	io.Copy(hasher, f)
	if fmt.Sprintf("%x", hasher.Sum(nil)) != "fc76f732918299cd3e5156a02beb3b42e8eb233e" {
		t.Fatal("copied file did not match")
	}
	p1.ShutdownNotify <- true
	p2.ShutdownNotify <- true
	p3.ShutdownNotify <- true
	wg.Wait()
}
func zTestTracker(t *testing.T) {
	tracker := bttest.NewTracker()
	defer tracker.Close()
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	meta.Announce = tracker.URL
	out := ioutil.Discard
	p1 := bt.NewPeer(meta, out)
	u, err := p1.TrackerURL()
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(u)
	defer res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	p2 := bt.NewPeer(meta, out)
	u, err = p2.TrackerURL()
	if err != nil {
		t.Fatal(err)
	}
	res, err = http.Get(u)
	defer res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	tr := new(bt.TrackerResponse)
	err = bencode.Unmarshal(res.Body, tr)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(tr.Peers))
	}
}
func zTestSimpleFile(t *testing.T) {
	wg := new(sync.WaitGroup)
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	p1, err := bttest.NewPeerWithDataPieces(meta, "centos-6.4.img.bz2", 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer p1.Close()

	p2, err := bttest.NewPeerWithDataPieces(meta, "centos-6.4.img.bz2", 50, 30)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	p4, err := bttest.NewPeerWithDataPieces(meta, "centos-6.4.img.bz2", meta.NumPieces-80, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer p4.Close()

	out := ioutil.Discard
	p3 := bt.NewPeer(meta, out)
	defer p3.Close()
	wg.Add(1)
	wg2 := new(sync.WaitGroup)
	go func() {
		p3.Connect(p1, p2, p4)
		wg.Done()
	}()
	wg2.Add(1) // this is our fetch finishing
	go func() {
		p3.Fetch()
		wg2.Done()
	}()
	wg2.Wait()
	wg.Wait()
}

func TestChunkerGetFile(t *testing.T) {
	wg := new(sync.WaitGroup)
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	out := ioutil.Discard
	p1 := bt.NewPeer(meta, out)

	wg.Add(1)
	go func() {
		f := <-p1.Chunker.DoneNotify()
		hasher := sha1.New()
		io.Copy(hasher, f)
		if fmt.Sprintf("%x", hasher.Sum(nil)) != "fc76f732918299cd3e5156a02beb3b42e8eb233e" {
			t.Fatal("copied file did not match")
		}
		p1.Close()
		wg.Done()
	}()
	f, err := os.Open("centos-6.4.img.bz2")
	if err != nil {
		t.Fatal(err)
	}

	n, err := io.Copy(p1.Chunker, f)
	if err != nil {
		t.Fatalf("err: %v, read %d bytes\n", err, n)
	}
	//	wg.Wait()
}
func TestChunkerWriter(t *testing.T) {
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	out := ioutil.Discard
	p1 := bt.NewPeer(meta, out)
	defer p1.Close()

	f, err := os.Open("centos-6.4.img.bz2")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(p1.Chunker, f)
	if err != nil {
		t.Fatalf("err: %v, read %d bytes\n", err, n)
	}
}

func TestPeerHandshake(t *testing.T) {
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	if err != nil {
		t.Fatal(err)
	}
	out := ioutil.Discard
	p1 := bt.NewPeer(meta, out)
	defer p1.Close()

	p2 := bt.NewPeer(meta, out)
	defer p2.Close()

	//	p1.Connect(p2.PeerAddr)
}

func TestPeerSend(t *testing.T) {
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	if err != nil {
		t.Fatal(err)
	}
	p1, err := bttest.NewPeerWithData(meta, "centos-6.4.img.bz2")
	if err != nil {
		t.Fatal(err)
	}
	defer p1.Close()
	out := ioutil.Discard
	p2 := bt.NewPeer(meta, out)
	defer p2.Close()

	//	p1.Connect(p2.PeerAddr)
}

func TestHandshakeHandler(t *testing.T) {
	/*
		pid := "remote PeerID       "
		h := &bt.Handshake{
			InfoHash: "lala5lala5lala5lala5",
			PeerId:   "lala5lala5lala5lala1",
		}
		out, err := h.MarshalBinary()
		p := bt.Peer{PeerId: pid}
		if err != nil {
			t.Fatal(err)
		}
		hs := bytes.NewReader(out)
		req, err := bt.NewRequest("example:4001", hs)
		if err != nil {
			t.Fatal(err)
		}
		w := bttest.NewRecorder()
		p.HandshakeHandler(w, req)
		out, err = ioutil.ReadAll(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		// rfc says it should be 68 bytes
		if len(out) != bt.HANDSHAKE_BYTES {
			t.Fatal("got bad handshake length")
		}
		h_resp := bt.Handshake{}
		if err := h_resp.UnmarshalBinary(out); err != nil {
			t.Fatal(err)
		}
		if h_resp.PeerId != pid {
			t.Fatalf("got bad peerId expected %s, got %s", pid, h_resp.PeerId)
		}
	*/
}

func TestCancelMsg(t *testing.T) {
	_, err := bt.Cancel(0, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBitfieldHandler(t *testing.T) {
	/*
		p := bt.Peer{RemotePeer: &bt.Peer{}}
		w := bttest.NewRecorder()
		bs := bt.NewBitset(3)
		req := &bt.Request{
			Payload:    bs.Bytes(),
			RemotePeer: &bt.Peer{},
		}
			p.BitfieldHandler(w, req)
			if bytes.Compare(bs.Bytes(), p.RemotePeer.Bitfield.Bytes()) != 0 {
				t.Fatalf("did not set remote peers bitfield correctly, expected %v, got %v", bs.Bytes(), p.RemotePeer.Bitfield.Bytes())
			}
	*/
}
func TestRequestHandler(t *testing.T) {
	/*
		p := bt.Peer{}
		w := bttest.NewRecorder()
		req := &bt.Request{
			Payload: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		}
		p.RequestHandler(w, req)
		msg_len := new(int32)
		if err := binary.Read(w.Body, binary.BigEndian, msg_len); err != nil {
			t.Fatal("err decoding msg len")
		}
		msg_type := new(int32)
		if err := binary.Read(w.Body, binary.BigEndian, msg_type); err != nil {
			t.Fatal("err decoding msg type")
		}
		if int(*msg_type) != bt.PIECE {
			t.Fatal("did not get a piece")
		}
	*/

}
