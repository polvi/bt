package bt

import (
	"bytes"
	"code.google.com/p/bencode-go"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
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
	Body       io.ReadCloser
	RemotePeer *Peer
	PeerAddr   string
	Id         int
	Payload    []byte
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

func (p *Peer) HandshakeHandler(w ResponseWriter, r *Request) (*Peer, error) {
	out := make([]byte, HANDSHAKE_BYTES)
	_, err := r.Body.Read(out)
	if err != nil {
		return nil, errors.New("error reading handshake: " + err.Error())
	}
	h := Handshake{}
	err = h.UnmarshalBinary(out)
	if err != nil {
		return nil, errors.New("error reading handshake: " + err.Error())
	}
	rp := &Peer{
		PeerId: h.PeerId,
	}

	if !p.handshake_sent {
		my_h := Handshake{
			InfoHash: p.MetaInfo.InfoHash,
			PeerId:   p.PeerId,
		}
		out, err = my_h.MarshalBinary()
		if err != nil {
			return nil, errors.New("error reading handshake: " + err.Error())
		}
		// send handshake response
		if _, err := w.Write(out); err != nil {
			return nil, errors.New("error reading handshake: " + err.Error())
		}
	}
	// now send bitfield
	bs, err := Bitfield(p.Bitfield.Bytes())
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(bs); err != nil {
		return nil, errors.New("error reading handshake: " + err.Error())
	}
	return rp, nil
}
func (p *Peer) ChokeHandler(w ResponseWriter, r *Request) {
	p.Choked = true
}

func (p *Peer) UnchokeHandler(w ResponseWriter, r *Request) {
	p.Choked = false
}
func (p *Peer) InterestedHandler(w ResponseWriter, r *Request) {
	p.Interested = true
}
func (p *Peer) UninterestedHandler(w ResponseWriter, r *Request) {
	p.Interested = false
}

/*
payload of length 4. The payload is a number denoting the index of a piece that the peer has successfully downloaded and validated. A peer receiving this message must validate the index and drop the connection if this index is not within the expected bounds. Also, a peer receiving this message MUST send an interested message to the sender if indeed it lacks the piece announced. Further, it MAY also send a request for that piece.
*/
func (p *Peer) HaveHandler(w ResponseWriter, r *Request) {
	piece := new(int32)
	if err := binary.Read(bytes.NewReader(r.Payload), binary.BigEndian, piece); err != nil {
		w.Close()
		return
	}
	pce := int(*piece)
	// validate index within bounds, drop conn otherwise
	if !p.Bitfield.InRange(pce) {
		w.Close()
	}

	// I have this piece, do nothing
	if p.Bitfield.IsSet(int(*piece)) {
		return
	}

	// if we got here, we need this piece
	m, err := Interested()
	if err != nil {
		w.Close()
	}
	w.Write(m)

	// XXX send request for piece?
}
func (p *Peer) BitfieldHandler(w ResponseWriter, r *Request) {
	bs, err := NewBitsetFromBytes(p.MetaInfo.NumPieces, r.Payload)
	if err != nil {
		fmt.Println(err)
		return
	}
	p.RemotePeer.Bitfield = bs
	i := p.Bitfield.FindNextClear(0)
	if i >= 0 && p.RemotePeer.Bitfield.IsSet(i) {
		out, err := RequestMsg(i, 0, int(p.MetaInfo.Info.PieceLength))
		if err != nil {
			fmt.Println(err)
			return
		}
		w.Write(out)

	}
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
	n, err := p.File.ReadAt(out, int64(offset))
	if err == io.EOF {
		out = out[:n]
	}
	if err != nil && err != io.EOF {
		fmt.Println("error reading file", err)
		return
	}
	fmt.Println(*piece, p.MetaInfo.Info.PieceLength, len(out))
	out, err = PieceMsg(int(*piece), int(*block_off), out)
	if err != nil {
		return
	}
	w.Write(out)
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
	off := (int(*piece) * int(p.MetaInfo.Info.PieceLength)) + int(*block_off)
	_, err = p.File.WriteAt(block_data, int64(off))
	if err != nil {
		fmt.Println(err)
		return
	}
	p.Bitfield.Set(int(*piece))
	i := p.Bitfield.FindNextClear(0)
	if i >= 0 && p.RemotePeer.Bitfield.IsSet(i) {
		out, err := RequestMsg(i, 0, int(p.MetaInfo.Info.PieceLength))
		if err != nil {
			fmt.Println(err)
			return
		}
		w.Write(out)
	}
}
func (p *Peer) CancelHandler(w ResponseWriter, r *Request) {
	// not sure what to do here
}
func (p *Peer) Connect(peerAddr string) error {
	hs := &Handshake{
		PeerId:   p.PeerId,
		InfoHash: p.MetaInfo.InfoHash,
	}
	out, err := hs.MarshalBinary()
	if err != nil {
		return err
	}
	req, err := NewRequest(peerAddr, bytes.NewReader(out))
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", req.PeerAddr)
	if err != nil {
		return err
	}
	if _, err := io.Copy(conn, req.Body); err != nil {
		return err
	}
	p.handshake_sent = true
	p.peer(conn)
	return nil
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
func Bitfield(bf []byte) ([]byte, error) {
	return message(BITFIELD, bf)
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

type Peer struct {
	PeerAddr       string
	PeerId         string
	Listener       net.Listener
	Handshake      bool
	Choked         bool
	Interested     bool
	MetaInfo       *MetaInfo
	Bitfield       *Bitset
	RemotePeer     *Peer
	File           *os.File
	handshake_sent bool
}

func (p *Peer) ReadRequest(b io.ReadCloser, peer *Peer) (req *Request, err error) {
	// if ml == 0, return
	// if ml > 1, get payload
	// if ml == 1 set id, no payload
	// assume Peer Wire Messages, read message length and type
	r := &Request{
		Id:         -1,
		RemotePeer: peer,
		Payload:    []byte{},
	}
	ml := new(int32)
	if err := binary.Read(b, binary.BigEndian, ml); err != nil {
		b.Close()
	}
	if *ml == 0 {
		// keepalive
		return r, nil
	}
	id := new(int8)
	if err := binary.Read(b, binary.BigEndian, id); err != nil {
		b.Close()
	}
	r.Id = int(*id)
	if *ml == 1 {
		// no payload
		return r, nil
	}
	// This is an integer which denotes the length of the message,
	// excluding the length part itself. If a message has no payload, its size is 1.
	payload := make([]byte, *ml-1)
	if err := binary.Read(b, binary.BigEndian, payload); err != nil {
		b.Close()
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
	}

	return fmt.Sprintf("-> %s %s %v bytes", r.RemotePeer.PeerId, m, len(r.Payload))
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
	}
	return nil, errors.New("unknown message")
}

// PeerA: connects, sends handshake
// PeerB: read handshake, write handshake, sends bitfield
// PeerA: read handshake, sends bitfield
func (p *Peer) peer(conn net.Conn) {
	remotePeer, err := p.HandshakeHandler(conn, &Request{Body: conn})
	if err != nil {
		conn.Close()
		fmt.Println("closing connection", err)
		return
	}
	p.RemotePeer = remotePeer
	fmt.Println(p.PeerId, "peered with", remotePeer.PeerId)
	for {
		r, err := p.ReadRequest(conn, remotePeer)
		if err != nil {
			conn.Close()
		}

		fmt.Println(p.PeerId, "request", r)
		h, err := p.FindHandler(r)
		if err != nil {
			conn.Close()
		}
		h.ServePWP(conn, r)
	}
}

func (p *Peer) Serve(l net.Listener) error {
	defer l.Close()
	for {
		conn, e := l.Accept()
		if e != nil {
			return e
		}
		go p.peer(conn)
	}
}

func (p *Peer) Close() {
	p.Listener.Close()
}

func NewTorrent(file string) (t *Torrent, err error) {
	tor := new(Torrent)
	meta, err := ReadTorrentMetaInfoFile(file)
	if err != nil {
		return nil, err
	}
	tor.MetaInfo = meta

	//	numPieces := int((meta.Info.Length + meta.Info.PieceLength - 1) / meta.Info.PieceLength)
	//	ref := []byte(meta.Info.Pieces)
	tor.PieceMap = make(map[string]int)

	pieces := tor.MetaInfo.GetPiecesList()
	for i, p := range pieces {
		tor.PieceMap[p] = i
	}
	//	tor.MetaInfo.DumpTorrentMetaInfo()
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
	var metaInfo MetaInfo
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

	// Decode bencoded metainfo file.
	fileMetaData, err := bencode.Decode(file)
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
