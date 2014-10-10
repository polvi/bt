package bt

import (
	"bytes"
	"code.google.com/p/bencode-go"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/polvi/bt/chunker"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type RoundTripper interface {
	RoundTrip(*Request) (*Response, error)
}

var DefaultTransport RoundTripper = &Transport{}

type Transport struct {
}

func (t *Transport) RoundTrip(req *Request) (resp *Response, err error) {
	// http://golang.org/src/pkg/net/http/transport.go
	conn, err := net.Dial("tcp", req.PeerAddr)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(conn, req.Body); err != nil {
		return nil, err
	}
	res := &Response{Body: conn}
	return res, nil
}

type Handler interface {
	ServePWP(ResponseWriter, *Request)
}

type ResponseWriter interface {
	Write([]byte) (int, error)
	Close() error
}

type Request struct {
	Body     io.ReadCloser
	PeerConn *PeerConn
	PeerAddr string
	Id       int
	Payload  []byte
}
type Response struct {
	Body io.ReadCloser
}

type HandlerFunc func(ResponseWriter, *Request)

func (f HandlerFunc) ServePWP(w ResponseWriter, r *Request) {
	f(w, r)
}

func NewRequest(peerAddr string, body io.Reader) (*Request, error) {
	rc, ok := body.(io.ReadCloser)
	if !ok && body != nil {
		rc = ioutil.NopCloser(body)
	}
	return &Request{Body: rc, PeerAddr: peerAddr}, nil
}

func (p *Peer) transport() RoundTripper {
	return DefaultTransport
}
func (p *Peer) send(req *Request) (*Response, error) {
	return send(req, p.transport())
}

func send(req *Request, t RoundTripper) (resp *Response, err error) {
	return t.RoundTrip(req)
}

func (p *Peer) Do(req *Request) (resp *Response, err error) {
	return p.send(req)
}

type Handshake struct {
	InfoHash string
	PeerId   string
}
type handshake struct {
	NameLength   uint8
	ProtocolName [19]byte
	Reserved     [8]byte
	InfoHash     [20]byte
	PeerId       [20]byte
}

func (h *Handshake) UnmarshalBinary(data []byte) error {
	hs := handshake{}
	if err := binary.Read(bytes.NewReader(data), binary.BigEndian, &hs); err != nil {
		return err
	}
	if int(hs.NameLength) != 19 {
		return errors.New("incorrect handshake header")
	}
	h.InfoHash = ""
	for i := 0; i < len(hs.InfoHash); i++ {
		h.InfoHash += string(hs.InfoHash[i])
	}
	h.PeerId = ""
	for i := 0; i < len(hs.InfoHash); i++ {
		h.PeerId += string(hs.PeerId[i])
	}
	return nil
}
func (h *Handshake) MarshalBinary() (data []byte, err error) {
	buf := new(bytes.Buffer)
	hs := handshake{}
	proto_name := "BitTorrent protocol"
	hs.NameLength = uint8(len(proto_name))

	for i := 0; i < len(proto_name); i++ {
		hs.ProtocolName[i] = proto_name[i]
	}
	for i := 0; i < 20; i++ {
		hs.InfoHash[i] = h.InfoHash[i]
	}
	for i := 0; i < 20; i++ {
		hs.PeerId[i] = h.PeerId[i]
	}

	err = binary.Write(buf, binary.BigEndian, hs)
	if err != nil {
		return []byte{}, err
	}
	return buf.Bytes(), nil
}

const HANDSHAKE_BYTES int = 68

func (p *Peer) ChokeHandler(w ResponseWriter, r *Request) {
	r.PeerConn.Choked = true
}

func (p *Peer) UnchokeHandler(w ResponseWriter, r *Request) {
	r.PeerConn.Choked = false
	p.FlushRequests(r.PeerConn)
}
func (p *Peer) InterestedHandler(w ResponseWriter, r *Request) {
	r.PeerConn.Interested = true
}
func (p *Peer) UninterestedHandler(w ResponseWriter, r *Request) {
	r.PeerConn.Interested = false
	r.PeerConn.RequestQueue = make(map[string]RequestQueueMsg)
}

/*
payload of length 4. The payload is a number denoting the index of a piece that the peer has successfully downloaded and validated. A peer receiving this message must validate the index and drop the connection if this index is not within the expected bounds. Also, a peer receiving this message MUST send an interested message to the sender if indeed it lacks the piece announced. Further, it MAY also send a request for that piece.
*/
func (p *Peer) HaveHandler(w ResponseWriter, r *Request) {
	pce := new(int32)
	if err := binary.Read(bytes.NewReader(r.Payload), binary.BigEndian, pce); err != nil {
		w.Close()
		return
	}
	piece := int(*pce)
	// validate index within bounds, drop conn otherwise
	if !p.Bitfield.InRange(piece) {
		r.PeerConn.Conn.Close()
	}

	// update my records for this remote peer
	r.PeerConn.RemotePeer.Bitfield.Set(piece)

	// I have this piece, do nothing
	if p.Bitfield.IsSet(piece) {
		return
	}

	// 6.3.7 a peer receiving this message MUST send an interested
	// message to the sender if indeed it lacks the piece announced.
	m, err := Interested()
	if err != nil {
		w.Close()
	}
	w.Write(m)
}

func (p *Peer) FlushRequests(pc *PeerConn) error {
	for _, r := range pc.RequestQueue {
		out := make([]byte, r.block_len)
		offset := (int(p.MetaInfo.Info.PieceLength) * r.piece) + r.block_off
		n, err := p.Chunker.GetFile().ReadAt(out, int64(offset))
		if err == io.EOF {
			out = out[:n]
		}
		if err != nil && err != io.EOF {
			fmt.Println("error reading file", err)
			return err
		}
		_, err = pc.Conn.Write(out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *Peer) BitfieldHandler(w ResponseWriter, r *Request) {
	bs, err := NewBitsetFromBytes(p.MetaInfo.NumPieces, r.Payload)
	if err != nil {
		fmt.Println(err)
		return
	}
	r.PeerConn.RemotePeer.Bitfield = bs
	p.BitfieldNotify <- r.PeerConn
}

func (p *Peer) RequestHandler(w ResponseWriter, r *Request) {
	rr := bytes.NewReader(r.Payload)
	piece := new(int32)
	if err := binary.Read(rr, binary.BigEndian, piece); err != nil {
		w.Close()
		return
	}
	block_off := new(int32)
	if err := binary.Read(rr, binary.BigEndian, block_off); err != nil {
		w.Close()
		return
	}
	block_len := new(int32)
	if err := binary.Read(rr, binary.BigEndian, block_len); err != nil {
		w.Close()
		return
	}
	out := make([]byte, *block_len)
	offset := (int(p.MetaInfo.Info.PieceLength) * int(*piece)) + int(*block_off)
	n, err := p.Chunker.GetFile().ReadAt(out, int64(offset))
	if err == io.EOF {
		out = out[:n]
		fmt.Println("short read", *piece, n)
	}
	if err != nil && err != io.EOF {
		fmt.Println("error reading file", err)
		return
	}
	//	if !r.PeerConn.Choked {
	out, err = PieceMsg(int(*piece), int(*block_off), out)
	if err != nil {
		return
	}
	w.Write(out)
	// uploaded bytes accounting
	p.uploaded += n
}
func (p *Peer) PieceHandler(w ResponseWriter, r *Request) {
	rr := bytes.NewReader(r.Payload)
	piece := new(int32)
	if err := binary.Read(rr, binary.BigEndian, piece); err != nil {
		w.Close()
		return
	}
	block_off := new(int32)
	if err := binary.Read(rr, binary.BigEndian, block_off); err != nil {
		w.Close()
		return
	}
	block_data, err := ioutil.ReadAll(rr)
	if err != nil {
		fmt.Println(err)
		return
	}
	n, err := p.Chunker.Apply(block_data)
	if err != nil {
		fmt.Println(err)
		return
	}
	// downloaded bytes accounting
	p.downloaded += n
	p.bytesLeft -= n
	if p.bytesLeft < 0 {
		panic("got negative bytes left")
	}
	p.Bitfield.Set(int(*piece))
	for _, pc := range p.PeerConns {
		p.SendHave(pc, int(*piece))
	}
	p.BitfieldNotify <- r.PeerConn
}
func (p *Peer) CancelHandler(w ResponseWriter, r *Request) {
	// not sure what to do here
	rr := bytes.NewReader(r.Payload)
	piece := new(int32)
	if err := binary.Read(rr, binary.BigEndian, piece); err != nil {
		w.Close()
		return
	}
	block_off := new(int32)
	if err := binary.Read(rr, binary.BigEndian, block_off); err != nil {
		w.Close()
		return
	}
	block_len := new(int32)
	if err := binary.Read(rr, binary.BigEndian, block_len); err != nil {
		w.Close()
		return
	}
	delete(r.PeerConn.RequestQueue, fmt.Sprintf("%d,%d,%d"))
}
func (p *Peer) NoOpHandler(w ResponseWriter, r *Request) {

}

type RequestQueueMsg struct {
	piece     int
	block_off int
	block_len int
}

func (p *Peer) Connect(peers ...*Peer) error {
	for _, rp := range peers {
		hs := &Handshake{
			PeerId:   p.PeerId,
			InfoHash: p.MetaInfo.InfoHash,
		}
		out, err := hs.MarshalBinary()
		if err != nil {
			return err
		}
		conn, err := net.Dial("tcp", rp.PeerAddr)
		if err != nil {
			return err
		}
		if _, err := io.Copy(conn, bytes.NewReader(out)); err != nil {
			return err
		}
		h, err := p.ReadHandshake(conn)
		if err != nil {
			conn.Close()
			return err
		}
		pc := p.NewPeerConn(conn, h.PeerId)
		if err := p.SendBitfield(pc); err != nil {
			pc.Conn.Close()
			return err
		}
		go p.handleRequests(pc)
		p.PeerNotify <- pc
	}
	return nil
}

func (p *Peer) NewPeerConn(conn net.Conn, id string) *PeerConn {
	return &PeerConn{
		Conn:         conn,
		RemotePeer:   &Peer{PeerId: id, Bitfield: NewBitset(p.MetaInfo.NumPieces)},
		Choked:       true,
		Interested:   false,
		RequestQueue: make(map[string]RequestQueueMsg),
	}
}

const (
	CHOKE        = 0
	UNCHOKE      = 1
	INTERESTED   = 2
	UNINTERESTED = 3
	HAVE         = 4
	BITFIELD     = 5
	REQUEST      = 6
	PIECE        = 7
	CANCEL       = 8
)

func message(id int, payload []byte) ([]byte, error) {
	size := 0
	if len(payload) == 0 {
		size = 1 //If a message has no payload, its size is 1.
	} else {
		size = len(payload) + 1
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(size)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int8(id)); err != nil {
		return []byte{}, err
	}
	if len(payload) > 0 {
		if _, err := buf.Write(payload); err != nil {
			return []byte{}, err
		}
	}
	return buf.Bytes(), nil
}

func Interested() ([]byte, error) {
	return message(INTERESTED, []byte{})
}
func (p *Peer) RarestFirst() int {
	// this needs to be smarter
	return p.Bitfield.FindNextClear(0)
}
func (p *Peer) tryPiece() {
	piece := p.RarestFirst()
	if piece < 0 {
		return
	}
	for _, pc := range p.PeerConns {
		if pc.RemotePeer.Bitfield.IsSet(piece) {
			pc.SendInterested()
			if p.MetaInfo.Info.Length < p.MetaInfo.Info.PieceLength {
				pc.SendRequest(piece, 0, int(p.MetaInfo.Info.Length))
			} else if p.bytesLeft < int(p.MetaInfo.Info.PieceLength) {
				pc.SendRequest(piece, 0, p.bytesLeft)
			} else {
				pc.SendRequest(piece, 0, int(p.MetaInfo.Info.PieceLength))
			}
			return
		}
	}
}
func (p *Peer) Fetch() error {
	tick := time.Tick(1 * time.Second)
	for {
		select {
		case pc := <-p.PeerNotify:
			if err := p.SendUnchoke(pc); err != nil {
				pc.Conn.Close()
				return err
			}
		case pc := <-p.BitfieldNotify:
			p.PeerConns[pc.RemotePeer.PeerId] = pc
			p.tryPiece()
		case <-tick:
			/*
				fmt.Println(p.PeerId, "                  ME\t", p.Bitfield)
				for pc := range p.PeerConns {
					peer := p.PeerConns[pc].RemotePeer
					fmt.Println(p.PeerId, peer.PeerId, "\t", peer.Bitfield)
				}
				fmt.Printf("dl: %d, up: %d, left: %d\n", p.downloaded, p.uploaded, p.bytesLeft)
			*/
		}
	}
}
func (p *Peer) SendUnchoke(pc *PeerConn) error {
	m, err := message(UNCHOKE, []byte{})
	if err != nil {
		return err
	}
	_, err = pc.Conn.Write(m)
	return err
}
func (p *Peer) SendBitfield(pc *PeerConn) error {
	bf := p.Bitfield.Bytes()
	m, err := message(BITFIELD, bf)

	if err != nil {
		return err
	}
	_, err = pc.Conn.Write(m)
	return err
}
func (pc *PeerConn) SendInterested() error {
	m, err := message(INTERESTED, []byte{})
	if err != nil {
		return err
	}
	_, err = pc.Conn.Write(m)
	return err
}

func (pc *PeerConn) SendRequest(piece int, block_off int, block_len int) error {
	m, err := RequestMsg(piece, block_off, block_len)
	if err != nil {
		return err
	}
	_, err = pc.Conn.Write(m)
	return err
}

func (p *Peer) SendHave(pc *PeerConn, piece int) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(piece)); err != nil {
		return err
	}
	m, err := message(HAVE, buf.Bytes())
	if err != nil {
		return err
	}
	_, err = pc.Conn.Write(m)
	return nil
}

// Piece Index | Block Offset | Block Length
func RequestMsg(pi int, bo int, bl int) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(pi)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(bo)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(bl)); err != nil {
		return []byte{}, err
	}

	return message(REQUEST, buf.Bytes())
}
func PieceMsg(pi int, bo int, bd []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(pi)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(bo)); err != nil {
		return []byte{}, err
	}
	if _, err := buf.Write(bd); err != nil {
		return []byte{}, err
	}

	return message(PIECE, buf.Bytes())
}

// Piece Index | Block Offset | Block Data
func Piece(pi int, bo int, bd []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(pi)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(bo)); err != nil {
		return []byte{}, err
	}
	if _, err := buf.Write(bd); err != nil {
		return []byte{}, err
	}

	return message(PIECE, buf.Bytes())
}

// Piece Index | Block Offset | Block Length
func Cancel(pi int, bo int, bl int) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, int32(pi)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(bo)); err != nil {
		return []byte{}, err
	}
	if err := binary.Write(buf, binary.BigEndian, int32(bl)); err != nil {
		return []byte{}, err
	}

	return message(CANCEL, buf.Bytes())
}

type PeerConn struct {
	handshake_sent bool
	Conn           net.Conn
	RemotePeer     *Peer
	Choked         bool
	Interested     bool
	RequestQueue   map[string]RequestQueueMsg
}
type Peer struct {
	PeerAddr       string
	PeerId         string
	Listener       net.Listener
	Handshake      bool
	MetaInfo       *MetaInfo
	Bitfield       *Bitset
	Chunker        *chunker.Chunker
	PeerConns      map[string]*PeerConn
	BitfieldNotify chan *PeerConn
	PeerNotify     chan *PeerConn
	PieceNotify    chan int
	ShutdownNotify chan bool
	uploaded       int
	downloaded     int
	bytesLeft      int
}

func (p *Peer) TrackerURL(event string) (string, error) {
	u := new(url.URL)
	q := u.Query()
	q.Add("info_hash", p.MetaInfo.InfoHash)
	q.Add("peer_id", p.PeerId)
	_, port, err := net.SplitHostPort(p.PeerAddr)
	if err != nil {
		return "", err
	}
	q.Add("port", port)
	// XXX This is a base ten integer value. It denotes the total amount of bytes that the peer has uploaded in the swarm since it sent the "started" event to the tracker. This key is REQUIRED.
	q.Add("uploaded", strconv.Itoa(p.uploaded))
	// XXX This is a base ten integer value. It denotes the total amount of bytes that the peer has downloaded in the swarm since it sent the "started" event to the tracker. This key is REQUIRED.
	q.Add("downloaded", strconv.Itoa(p.downloaded))
	q.Add("left", strconv.Itoa(p.bytesLeft))
	if event != "" {
		q.Add("event", event)
	}
	q.Add("numwant", "100")
	u.RawQuery = q.Encode()
	return fmt.Sprintf("%s%s", p.MetaInfo.Announce, u), nil
}
func (p *Peer) ReadHandshake(conn net.Conn) (h Handshake, err error) {
	out := make([]byte, HANDSHAKE_BYTES)
	_, err = conn.Read(out)
	if err != nil {
		return Handshake{}, errors.New("error reading handshake: " + err.Error())
	}
	h = Handshake{}
	err = h.UnmarshalBinary(out)
	if err != nil {
		return Handshake{}, errors.New("error reading handshake: " + err.Error())
	}
	return h, nil
}
func (p *Peer) ReadRequest(pc *PeerConn) (req *Request, err error) {
	// if ml == 0, return
	// if ml > 1, get payload
	// if ml == 1 set id, no payload
	// assume Peer Wire Messages, read message length and type
	r := &Request{
		Id:       -1,
		PeerConn: pc,
		Payload:  []byte{},
	}
	ml := new(int32)
	if err := binary.Read(pc.Conn, binary.BigEndian, ml); err != nil {
		pc.Conn.Close()
	}
	if *ml == 0 {
		// keepalive
		return r, nil
	}
	id := new(int8)
	if err := binary.Read(pc.Conn, binary.BigEndian, id); err != nil {
		pc.Conn.Close()
	}
	r.Id = int(*id)
	if *ml == 1 {
		// no payload
		return r, nil
	}
	// This is an integer which denotes the length of the message,
	// excluding the length part itself. If a message has no payload, its size is 1.
	payload := make([]byte, *ml-1)
	if err := binary.Read(pc.Conn, binary.BigEndian, payload); err != nil {
		pc.Conn.Close()
	}
	r.Payload = payload
	return r, nil
}
func (r *Request) String() string {
	m := "unknown"
	switch r.Id {
	case CHOKE:
		m = "choke"
	case UNCHOKE:
		m = "unchoke"
	case INTERESTED:
		m = "interested"
	case UNINTERESTED:
		m = "uninterested"
	case HAVE:
		m = "have"
	case BITFIELD:
		m = "bitfield"
	case REQUEST:
		m = "request"
	case PIECE:
		m = "piece"
	case CANCEL:
		m = "cancel"
	default:
		m = fmt.Sprintf("unknown [%d]", r.Id)
	}

	return fmt.Sprintf("-> %s %s %v bytes", r.PeerConn.RemotePeer.PeerId, m, len(r.Payload))
}

func (p *Peer) FindHandler(r *Request) (HandlerFunc, error) {
	switch r.Id {
	case CHOKE:
		return p.ChokeHandler, nil
	case UNCHOKE:
		return p.UnchokeHandler, nil
	case INTERESTED:
		return p.InterestedHandler, nil
	case UNINTERESTED:
		return p.UninterestedHandler, nil
	case HAVE:
		return p.HaveHandler, nil
	case BITFIELD:
		return p.BitfieldHandler, nil
	case REQUEST:
		return p.RequestHandler, nil
	case PIECE:
		return p.PieceHandler, nil
	case CANCEL:
		return p.CancelHandler, nil
	case -1:
		// keep alive
		return p.NoOpHandler, nil
	}
	return nil, errors.New("unknown message")
}

func (p *Peer) handleRequests(pc *PeerConn) {
	for {
		r, err := p.ReadRequest(pc)
		if err != nil {
			pc.Conn.Close()
		}

		//		fmt.Println(p.PeerId, "request", r)
		h, err := p.FindHandler(r)
		if err != nil {
			pc.Conn.Close()
		}
		h.ServePWP(pc.Conn, r)
	}
}

func (p *Peer) Serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, e := l.Accept()
		if e != nil {
			return e
		}
		h, err := p.ReadHandshake(conn)
		if err != nil {
			conn.Close()
			return errors.New("error reading handshake: " + err.Error())
		}
		// send my handshake
		my_h := Handshake{
			InfoHash: p.MetaInfo.InfoHash,
			PeerId:   p.PeerId,
		}
		out, err := my_h.MarshalBinary()
		if err != nil {
			conn.Close()
			return errors.New("error reading handshake: " + err.Error())
		}
		if _, err := conn.Write(out); err != nil {
			conn.Close()
			return errors.New("error reading handshake: " + err.Error())
		}

		pc := p.NewPeerConn(conn, h.PeerId)
		// initialize bitfield incase remote end does not send one
		if err := p.SendBitfield(pc); err != nil {
			pc.Conn.Close()
			return err
		}
		go p.handleRequests(pc)
		p.PeerNotify <- pc
	}
}

func NewPeer(meta *MetaInfo, out io.Writer) *Peer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("failed to listen on a port: %v", err))
		}
	}
	p := &Peer{PeerAddr: l.Addr().String(), Listener: l}
	id := make([]byte, 20)
	_, err = rand.Read(id)
	if err != nil {
		panic(fmt.Sprintf("failed to get peerid: %v", err))
	}
	i := fmt.Sprintf("%x", id)
	p.PeerId = fmt.Sprintf("gobt-%s", i[:15])
	p.MetaInfo = meta

	p.Bitfield = NewBitset(meta.NumPieces)
	c, err := chunker.NewChunker(
		p.MetaInfo.PiecesList,
		int(p.MetaInfo.Info.PieceLength),
		int(p.MetaInfo.Info.Length),
		out)
	if err != nil {
		panic(fmt.Sprintf("unable to create chunker"))
	}
	p.Chunker = c
	p.PeerConns = make(map[string]*PeerConn)
	p.PeerNotify = make(chan *PeerConn)
	p.PieceNotify = make(chan int)
	p.BitfieldNotify = make(chan *PeerConn)
	p.ShutdownNotify = make(chan bool)
	p.uploaded = 0
	p.downloaded = 0
	p.bytesLeft = int(meta.Info.Length)
	go p.Serve(p.Listener)
	return p
}
func (p *Peer) Start() error {
	go p.Fetch()
	tr, err := p.TrackerUpdate("started")
	if err != nil {
		return err
	}
	tick := time.Tick(time.Second * time.Duration(tr.Interval))
	for {
		select {
		case <-p.ShutdownNotify:
			_, err := p.TrackerUpdate("stopped")
			if err != nil {
				return err
			}
			return nil
			/*
				case <-p.Chunker.DoneNotify():
					_, err := p.TrackerUpdate("completed")
					if err != nil {
						return err
					}
			*/
		case <-tick:
			_, err := p.TrackerUpdate("")
			if err != nil {
				return err
			}
		}
	}
}

type TrackerPeer struct {
	PeerId string "peer id"
	Ip     string "ip"
	Port   int    "port"
}
type TrackerResponse struct {
	Interval int           "interval"
	Peers    []TrackerPeer "peers"
}

func (p *Peer) TrackerUpdate(event string) (*TrackerResponse, error) {
	u, err := p.TrackerURL(event)
	if err != nil {
		return nil, err
	}
	res, err := http.Get(u)
	defer res.Body.Close()
	if err != nil {
		return nil, err
	}
	tr := new(TrackerResponse)
	err = bencode.Unmarshal(res.Body, tr)
	if err != nil {
		return nil, err
	}
	for _, peer := range tr.Peers {
		if _, ok := p.PeerConns[peer.PeerId]; !ok {
			if peer.PeerId == p.PeerId {
				continue
			}
			rp := &Peer{
				PeerAddr: fmt.Sprintf("%s:%d", peer.Ip, peer.Port),
			}
			go p.Connect(rp)
		}
	}
	return tr, nil
}

func (p *Peer) Close() {
	p.Listener.Close()
	p.Chunker.Cleanup()
}

func NewTorrent(file string) (t *Torrent, err error) {
	tor := new(Torrent)
	meta, err := ReadTorrentMetaInfoFile(file)
	if err != nil {
		return nil, err
	}
	tor.MetaInfo = meta
	tor.PieceMap = make(map[string]int)

	pieces := tor.MetaInfo.GetPiecesList()
	for i, p := range pieces {
		tor.PieceMap[p] = i
	}
	return tor, nil
}

type Torrent struct {
	MetaInfo *MetaInfo
	PieceMap map[string]int
}

// Structs into which torrent metafile is
// parsed and stored into.
type FileDict struct {
	Length int64    "length"
	Path   []string "path"
	Md5sum string   "md5sum"
}

type InfoDict struct {
	FileDuration []int64 "file-duration"
	FileMedia    []int64 "file-media"
	// Single file
	Name   string "name"
	Length int64  "length"
	Md5sum string "md5sum"
	// Multiple files
	Files       []FileDict "files"
	PieceLength int64      "piece length"
	Pieces      string     "pieces"
	Private     int64      "private"
}

type MetaInfo struct {
	Info         InfoDict   "info"
	InfoHash     string     "info hash"
	Announce     string     "announce"
	AnnounceList [][]string "announce-list"
	CreationDate int64      "creation date"
	Comment      string     "comment"
	CreatedBy    string     "created by"
	Encoding     string     "encoding"

	NumPieces  int
	PiecesList []string
}

// Open .torrent file, un-bencode it and load them into MetaInfo struct.
func ReadTorrentMetaInfoFile(fileNameWithPath string) (meta *MetaInfo, err error) {
	// Check exntension.
	if fileExt := filepath.Ext(fileNameWithPath); fileExt != ".torrent" {
		return nil, errors.New("file extention required to be .torrent")
	}

	// Open file now.
	file, err := os.Open(fileNameWithPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ReadTorrentMetaInfo(file)
}
func ReadTorrentMetaInfo(r io.Reader) (meta *MetaInfo, err error) {
	var metaInfo MetaInfo
	// Decode bencoded metainfo file.
	fileMetaData, err := bencode.Decode(r)
	if err != nil {
		return nil, err
	}

	// fileMetaData is map of maps of... maps. Get top level map.
	metaInfoMap, ok := fileMetaData.(map[string]interface{})
	if !ok {
		return nil, errors.New("unable to find metadata")
	}

	// Enumerate through child maps.
	var bytesBuf bytes.Buffer
	for mapKey, mapVal := range metaInfoMap {
		switch mapKey {
		case "info":
			if err = bencode.Marshal(&bytesBuf, mapVal); err != nil {
				return nil, err
			}

			infoHash := sha1.New()
			infoHash.Write(bytesBuf.Bytes())
			metaInfo.InfoHash = string(infoHash.Sum(nil))

			if err = bencode.Unmarshal(&bytesBuf, &metaInfo.Info); err != nil {
				return nil, err
			}

		case "announce-list":
			if err = bencode.Marshal(&bytesBuf, mapVal); err != nil {
				return nil, err
			}
			if err = bencode.Unmarshal(&bytesBuf, &metaInfo.AnnounceList); err != nil {
				return nil, err
			}

		case "announce":
			metaInfo.Announce = mapVal.(string)

		case "creation date":
			metaInfo.CreationDate = mapVal.(int64)

		case "comment":
			metaInfo.Comment = mapVal.(string)

		case "created by":
			metaInfo.CreatedBy = mapVal.(string)

		case "encoding":
			metaInfo.Encoding = mapVal.(string)
		}
	}

	metaInfo.PiecesList = metaInfo.GetPiecesList()
	metaInfo.NumPieces = len(metaInfo.PiecesList)
	return &metaInfo, nil
}

// Print torrent meta info struct data.
func (metaInfo *MetaInfo) DumpTorrentMetaInfo() {
	fmt.Println("Announce:", metaInfo.Announce)
	fmt.Println("Announce List:")
	for _, anncListEntry := range metaInfo.AnnounceList {
		for _, elem := range anncListEntry {
			fmt.Println("    ", elem)
		}
	}
	strCreationDate := time.Unix(metaInfo.CreationDate, 0)
	fmt.Println("Creation Date:", strCreationDate)
	fmt.Println("Comment:", metaInfo.Comment)
	fmt.Println("Created By:", metaInfo.CreatedBy)
	fmt.Println("Encoding:", metaInfo.Encoding)
	fmt.Printf("InfoHash: %X\n", metaInfo.InfoHash)
	fmt.Println("Info:")
	fmt.Println("    Piece Length:", metaInfo.Info.PieceLength)
	piecesList := metaInfo.GetPiecesList()
	fmt.Printf("    Pieces:%X -- %X\n", len(piecesList), len(metaInfo.Info.Pieces)/20)
	fmt.Println("    File Duration:", metaInfo.Info.FileDuration)
	fmt.Println("    File Media:", metaInfo.Info.FileMedia)
	fmt.Println("    Private:", metaInfo.Info.Private)
	fmt.Println("    Name:", metaInfo.Info.Name)
	fmt.Println("    Length:", metaInfo.Info.Length)
	fmt.Println("    Md5sum:", metaInfo.Info.Md5sum)
	fmt.Println("    Files:")
	for _, fileDict := range metaInfo.Info.Files {
		fmt.Println("        Length:", fileDict.Length)
		fmt.Println("        Path:", fileDict.Path)
		fmt.Println("        Md5sum:", fileDict.Md5sum)
	}
}

// Splits pieces string into an array of 20 byte SHA1 hashes.
func (metaInfo *MetaInfo) GetPiecesList() []string {
	var piecesList []string
	piecesLen := len(metaInfo.Info.Pieces)
	for i := 0; i < piecesLen; i = i + 20 {
		piecesList = append(piecesList, metaInfo.Info.Pieces[i:i+20])
	}
	return piecesList
}
