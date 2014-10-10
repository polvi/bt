package main

import (
	"flag"
	"fmt"
	"github.com/polvi/bt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func main() {
	var webseed = flag.Bool("webseed", false, "seed by downloading from S3 over http first")
	var s3url = flag.String("url", "", "url to download")
	flag.Parse()
	if *s3url == "" {
		flag.Usage()
		os.Exit(1)
	}
	res, err := http.Get(*s3url + "?torrent")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer res.Body.Close()
	if s, ok := res.Header["Server"]; ok {
		if s[0] != "AmazonS3" {
			fmt.Println("this script only works with Amazon S3")
			os.Exit(1)
		}
	}
	ur, err := url.Parse(*s3url)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	filename := filepath.Base(ur.Path)
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	meta, err := bt.ReadTorrentMetaInfo(res.Body)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	p := bt.NewPeer(meta, f)
	defer p.Close()

	go func() {
		tick := time.NewTicker(1 * time.Second)
		for {
			fmt.Println(p.Chunker.GetBitfield())
			<-tick.C
		}
	}()
	if *webseed {
		go func() {
			res, err := http.Get(*s3url)
			if err != nil {
				fmt.Println(err)
			}
			defer res.Body.Close()
			if _, err := io.Copy(p.Chunker, res.Body); err != nil {
				fmt.Println(err)
			}
		}()
	}
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
		os.Remove(filename)
		p.ShutdownNotify <- true
	}()
	// graceful shutdown on file being done
	go func() {
		<-p.Chunker.DoneNotify()
		if !*webseed {
			p.ShutdownNotify <- true
		}
	}()
	wg.Wait()
}
