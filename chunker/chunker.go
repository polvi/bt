package chunker

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/polvi/bttp/bt"
	"hash"
	"io"
	"io/ioutil"
	"os"
)

type Chunker struct {
	Done           chan *os.File
	hasher         hash.Hash
	t              bt.Torrent
	file           *os.File
	hashMap        map[string]int
	doneMap        map[int]bool
	chunkSize      int
	fileSize       int
	nextWritePiece int
	out            io.Writer

	buf        []byte
	bytes_left int
}

func NewChunker(hashList []string, chunkSize int, fileSize int, out io.Writer) (*Chunker, error) {
	c := new(Chunker)
	file, err := ioutil.TempFile("", "chunker")
	if err != nil {
		return nil, err
	}
	file.Truncate(int64(fileSize))
	c.file = file
	c.hasher = sha1.New()
	c.hashMap = make(map[string]int)
	for i, h := range hashList {
		c.hashMap[h] = i
	}
	c.chunkSize = chunkSize
	c.fileSize = fileSize
	c.nextWritePiece = 0
	c.out = out
	c.buf = []byte{}
	c.bytes_left = c.fileSize
	c.Done = make(chan *os.File, 1)
	c.doneMap = make(map[int]bool)
	return c, nil
}

func (c *Chunker) Read(p []byte) (n int, err error) {
	/*
		n, err = c.bufReader.Read(p)
		if err != nil {
			return n, err
		}
		if c.completed == len(c.hashMap) {
			return n, io.EOF
		}
	*/
	return 0, nil
}

// Write provides a io.Writer interface for applying chunks.
// Note that the beginningio.Reader must be aligned with a valid chunk.
// Use Flush() to write final set of data out
func (c *Chunker) Write(p []byte) (n int, err error) {
	c.buf = append(c.buf, p...)
	if c.chunkSize >= c.fileSize && c.fileSize == len(c.buf) {
		n, err = c.Apply(p)
		if err != nil {
			return n, err
		}
		c.bytes_left -= n
		return len(p), err
	}
	for c.bytes_left > 0 && len(c.buf) > c.chunkSize {
		b := c.buf[:c.chunkSize]
		n, err = c.Apply(b)
		if err != nil {
			return n, err
		}
		c.buf = c.buf[c.chunkSize:]
		c.bytes_left -= c.chunkSize
	}
	if c.bytes_left < c.chunkSize && len(c.buf) == c.bytes_left {
		n, err = c.Apply(p)
		if err != nil {
			return n, err
		}
		c.bytes_left -= len(c.buf)
		return len(p), nil
	}
	return len(p), nil
}
func (c *Chunker) Flush() (err error) {
	_, err = c.Apply(c.buf)
	if err != nil {
		return err
	}
	c.bytes_left -= len(c.buf)
	c.buf = []byte{}
	return nil
}

func (c *Chunker) DoneNotify() chan *os.File {
	return c.Done
}
func (c *Chunker) GetFile() *os.File {
	return c.file
}
func (c *Chunker) Apply(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.hasher.Reset()
	c.hasher.Write(b)
	sum := c.hasher.Sum(nil)

	// returns zero bytes if it could not verify the data
	i, ok := c.hashMap[string(sum)]
	if !ok {
		return 0, errors.New(fmt.Sprintf("got unknown chunk, size %d, chunk size %d", len(b), c.chunkSize))
	}
	if _, ok := c.doneMap[i]; ok {
		// we've already applied this one, no error
		return len(b), nil
	}
	// does it need to be sync'd?
	n, err := c.file.WriteAt(b, int64(i*c.chunkSize))
	if err != nil {
		return n, err
	}
	c.doneMap[i] = true
	if len(c.doneMap) == len(c.hashMap) {
		c.Done <- c.file
	}
	if c.nextWritePiece == i {
		_, err := c.out.Write(b)
		if err != nil {
			return n, err
		}
		c.nextWritePiece++
		j := c.nextWritePiece
		for j = i; j < len(c.hashMap); j++ {
			if _, ok := c.doneMap[j]; !ok {
				break
			}
		}
		if j > c.nextWritePiece {
			// read everything between these chunks and write it all at once
			buf := make([]byte, ((j - c.nextWritePiece) * c.chunkSize))
			n2, err := c.file.ReadAt(buf, int64(c.chunkSize*c.nextWritePiece))
			if err == io.EOF {
				buf = buf[:n2]
			}
			if err != nil && err != io.EOF {
				return n, err
			}
			_, err = c.out.Write(buf)
			if err != nil {
				return n, err
			}
		}
		c.nextWritePiece = j
	}
	return n, nil
}

func (c *Chunker) Cleanup() error {
	if err := c.file.Close(); err != nil {
		return err
	}
	if err := os.Remove(c.file.Name()); err != nil {
		return err
	}
	return nil
}
