package bttest

import (
	"bytes"
	"fmt"
	bencode "github.com/jackpal/bencode-go"
	"net"
	"net/http"
	"strconv"
)

type trackerPeer struct {
	ip         string
	port       int
	uploaded   int
	downloaded int
	left       int
}

type TrackerServer struct {
	URL      string
	Listener net.Listener
	Config   *http.Server
}
type trackerStatus struct {
	peers map[string]map[string]trackerPeer // info_hash, peer_id, trackerPeer
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

func announceHandler(w http.ResponseWriter, r *http.Request, s *trackerStatus) {
	v := r.URL.Query()
	if _, ok := s.peers[v.Get("info_hash")]; !ok {
		s.peers[v.Get("info_hash")] = make(map[string]trackerPeer)
	}
	if _, ok := s.peers[v.Get("info_hash")][v.Get("peer_id")]; !ok {
		t := trackerPeer{}
		if port, err := strconv.Atoi(v.Get("port")); err == nil {
			t.port = port
		}
		if uploaded, err := strconv.Atoi(v.Get("uploaded")); err == nil {
			t.uploaded = uploaded
		}
		if downloaded, err := strconv.Atoi(v.Get("downloaded")); err == nil {
			t.downloaded = downloaded
		}
		if left, err := strconv.Atoi(v.Get("left")); err == nil {
			t.left = left
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			fmt.Fprintf(w, "error parsing host "+err.Error())
			return
		}
		t.ip = host
		s.peers[v.Get("info_hash")][v.Get("peer_id")] = t
	}
	tr := TrackerResponse{Interval: 1}
	if p, ok := s.peers[v.Get("info_hash")]; ok {
		for k, tp := range p {
			tr.Peers = append(tr.Peers, TrackerPeer{
				PeerId: k,
				Ip:     tp.ip,
				Port:   tp.port,
			})
		}
	}
	var b bytes.Buffer
	err := bencode.Marshal(&b, tr)
	if err != nil {
		fmt.Fprintf(w, "error writing bencode "+err.Error())
		return
	}
	w.Write(b.Bytes())
}

func newLocalListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("httptest: failed to listen on a port: %v", err))
		}
	}
	return l
}
func (s *TrackerServer) Close() {
	s.Listener.Close()
}

func NewTracker() *TrackerServer {
	status := &trackerStatus{
		peers: make(map[string]map[string]trackerPeer),
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		announceHandler(w, r, status)
	})
	ts := &TrackerServer{
		Listener: newLocalListener(),
		Config:   &http.Server{},
	}
	ts.URL = "http://" + ts.Listener.Addr().String() + "/"
	go ts.Config.Serve(ts.Listener)
	return ts
}
