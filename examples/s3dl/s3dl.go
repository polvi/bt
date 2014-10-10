package main

import (
	"fmt"
	"github.com/polvi/bt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
)

func usage() {
	fmt.Printf("Usage: %s http://s3.amazon....\n", os.Args[0])
	os.Exit(1)
}
func main() {
	if len(os.Args) != 2 {
		usage()
	}
	u := os.Args[1]
	ur, err := url.Parse(u)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	out := filepath.Base(ur.Path)
	f, err := os.Create(out)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	res, err := http.Get(u)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer res.Body.Close()
	meta, err := bt.ReadTorrentMetaInfo(res.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	p := bt.NewPeer(meta, f)
	defer p.Close()
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		p.Start()
		f.Close()
		wg.Done()
	}()
	// graceful shutdown on ctrl+c
	go func() {
		ch := make(chan os.Signal)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		f.Close()
		os.Remove(out)
		p.ShutdownNotify <- true
	}()
	// graceful shutdown on file being done
	go func() {
		<-p.Chunker.DoneNotify()
		p.ShutdownNotify <- true
	}()
	wg.Wait()
}
