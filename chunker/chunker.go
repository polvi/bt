package chunker

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
)

type Chunker struct {
	Done           chan *os.File
	hasher         hash.Hash
	chunks         []*Chunk
	chunksDone     int
	chunksTotal    int
	file           *os.File
	chunkSize      int
	fileSize       int
	nextWritePiece int
	out            io.Writer

	buf        []byte
	bytes_left int
}

type Chunk struct {
	hash    string
	applied bool
}

func NewChunker(hashList []string, chunkSize int, fileSize int, out io.Writer) (*Chunker, error) {
	c := new(Chunker)
	file, err := ioutil.TempFile("", "chunker")
	if err != nil {
		return nil, err
	}
	err = file.Truncate(int64(fileSize))
	if err != nil {
		return nil, err
	}
	c.file = file
	c.hasher = sha1.New()
	c.chunksDone = 0
	c.chunksTotal = len(hashList)
	c.chunks = make([]*Chunk, len(hashList))
	for i, h := range hashList {
		c.chunks[i] = &Chunk{
			hash:    h,
			applied: false,
		}
	}
	c.chunkSize = chunkSize
	c.fileSize = fileSize
	c.nextWritePiece = 0
	c.out = out
	c.buf = []byte{}
	c.bytes_left = c.fileSize
	c.Done = make(chan *os.File, 1)
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

func (c *Chunker) findChunk(hash string) (*Chunk, int, error) {
	for i, c := range c.chunks {
		if c.hash == hash && !c.applied {
			return c, i, nil
		}
	}
	return nil, 0, errors.New("unable to find chunk with hash " + hash)
}
func (c *Chunker) Apply(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.hasher.Reset()
	c.hasher.Write(b)
	sum := string(c.hasher.Sum(nil))

	chunk, piece, err := c.findChunk(sum)
	if err != nil {
		fmt.Println(err)
		return 0, errors.New(fmt.Sprintf("got unknown chunk, size %d, chunk size %d", len(b), c.chunkSize))
	}
	// XXX I think there is a race here
	if chunk.applied {
		// we already wrote it, no op
		return 0, nil
	}
	n, err := c.file.WriteAt(b, int64(piece*c.chunkSize))
	if err != nil {
		return n, err
	}
	chunk.applied = true
	// XXX: I think there is a race between here and above
	c.chunksDone += 1
	if c.nextWritePiece == piece {
		_, err := c.out.Write(b)
		if err != nil {
			return n, err
		}
		c.nextWritePiece++
		j := c.nextWritePiece
		for j = piece; j < len(c.chunks); j++ {
			if chunk := c.chunks[j]; !chunk.applied {
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
	if c.chunksDone == c.chunksTotal {
		c.file.Sync()
		c.Done <- c.file
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
