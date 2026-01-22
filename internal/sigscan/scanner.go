package sigscan

import (
	"os"
)

// Must own /proc/<pid>/mem to read it
type Scanner struct {
	pid string
	mem *os.File
}

func NewScanner(pid string) (*Scanner, error) {
	mem, err := os.OpenFile("/proc/"+pid+"/mem", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return &Scanner{pid: pid, mem: mem}, nil
}

func (s *Scanner) Close() error {
	return s.mem.Close()
}
