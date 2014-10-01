package main

import (
	"bytes"
	"github.com/polvi/bt"
	"github.com/polvi/bt/bttest"
	"io/ioutil"
	"testing"
)

/*
6.2 Handshaking
http://jonas.nitro.dk/bittorrent/bittorrent-rfc.html
*/

func TestPeerHandshake(t *testing.T) {
	meta, err := bt.ReadTorrentMetaInfoFile("centos-6.4.img.bz2.torrent")
	if err != nil {
		t.Fatal(err)
	}
	p1 := bttest.NewPeer(meta)
	defer p1.Close()

	p2 := bttest.NewPeer(meta)
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

	p2 := bttest.NewPeer(meta)
	defer p2.Close()

	p1.Connect(p2.PeerAddr)
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

func TestHaveHandler(t *testing.T) {
	p := bt.Peer{}
	p.Bitfield = bt.NewBitset(10)
	w := bttest.NewRecorder()
	req := &bt.Request{
		Payload: []byte{0, 0, 0, 1},
	}
	p.HaveHandler(w, req)
	out, err := ioutil.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	i, _ := bt.Interested()
	if bytes.Compare(out, i) != 0 {
		t.Fatalf("got bad response from HaveHandler")
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
