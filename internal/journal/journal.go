// Package journal writes AFP messages as JSON Lines with size-based rotation,
// so an attacker cannot fill a Pi's SD card by generating log volume.
package journal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Journal struct {
	mu      sync.Mutex
	path    string
	max     int64
	keep    int
	f       *os.File
	w       *bufio.Writer
	size    int64
	out     io.Writer // when set (tests, stdout), rotation is off
	Dropped uint64
	// rate cap: at most burst lines per second, beyond that lines are counted and dropped
	burst  int
	second int64
	inSec  int
}

func Open(path string, maxMB, keep int) (*Journal, error) {
	j := &Journal{path: path, max: int64(maxMB) << 20, keep: keep, burst: 2000}
	if path == "-" {
		j.out = os.Stdout
		return j, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	return j, j.open()
}

// NewWriter journals to w without rotation.
func NewWriter(w io.Writer) *Journal { return &Journal{out: w, burst: 1 << 30} }

func (j *Journal) open() error {
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	j.f, j.w, j.size = f, bufio.NewWriterSize(f, 64<<10), st.Size()
	return nil
}

func (j *Journal) rotate() error {
	_ = j.w.Flush()
	_ = j.f.Close()
	for i := j.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", j.path, i), fmt.Sprintf("%s.%d", j.path, i+1))
	}
	if j.keep > 0 {
		_ = os.Rename(j.path, j.path+".1")
	} else {
		_ = os.Remove(j.path)
	}
	return j.open()
}

// Write appends one message. Errors are swallowed after counting: logging
// must never stop the firewall.
func (j *Journal) Write(msg any) {
	b, err := json.Marshal(msg)
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if s := time.Now().Unix(); s != j.second {
		j.second, j.inSec = s, 0
	}
	if j.inSec++; j.inSec > j.burst {
		j.Dropped++
		return
	}
	b = append(b, '\n')
	if j.out != nil {
		_, _ = j.out.Write(b)
		return
	}
	if j.max > 0 && j.size+int64(len(b)) > j.max {
		if err := j.rotate(); err != nil {
			j.Dropped++
			return
		}
	}
	n, err := j.w.Write(b)
	j.size += int64(n)
	if err != nil {
		j.Dropped++
	}
}

func (j *Journal) Flush() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.w != nil {
		_ = j.w.Flush()
	}
}

func (j *Journal) Close() error {
	j.Flush()
	if j.f != nil {
		return j.f.Close()
	}
	return nil
}
