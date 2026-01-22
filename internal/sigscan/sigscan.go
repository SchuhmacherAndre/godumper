package sigscan

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type Region struct {
	Start uintptr
	End   uintptr
	Perms string
	Path  string
}

func (s *Scanner) ScanAll(pattern []byte, wildcard byte) ([]uintptr, error) {
	regions, err := s.Regions()
	if err != nil {
		return nil, err
	}

	var matches []uintptr
	for _, r := range regions {
		addr, found, err := s.ScanRegion(r.Start, r.End-r.Start, pattern, wildcard)
		if err != nil {
			continue
		}
		if found {
			matches = append(matches, addr)
		}
	}
	return matches, nil
}

func (s *Scanner) ScanRegion(
	addr uintptr,
	size uintptr,
	pattern []byte,
	wildcard byte,
) (uintptr, bool, error) {
	const chunkSize = 64 * 1024 // aim for 64KB chunks
	buf := make([]byte, chunkSize+len(pattern))
	var offset uintptr

	for offset < size {
		readSize := min(chunkSize, size-offset)

		n, err := syscall.Pread(
			int(s.mem.Fd()),
			buf[:readSize],
			int64(addr+offset),
		)

		if err != nil || n <= 0 {
			return 0, false, err
		}

		if idx := scanBytes(buf[:n], pattern, wildcard); idx >= 0 {
			return addr + offset + uintptr(idx), true, nil
		}

		// overlap to catch patterns spanning chunks
		offset += uintptr(n)
	}
	return 0, false, nil
}

func (s *Scanner) Regions() ([]Region, error) {
	f, err := os.Open("/proc/" + s.pid + "/maps")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var regions []Region
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		addrRange := parts[0]
		perms := parts[1]
		path := ""
		if len(parts) >= 6 {
			path = parts[5]
		}

		if !strings.Contains(perms, "r") {
			continue // skip non-readable regions
		}

		addrs := strings.Split(addrRange, "-")
		start, _ := strconv.ParseUint(addrs[0], 16, 64)
		end, _ := strconv.ParseUint(addrs[1], 16, 64)

		regions = append(regions, Region{
			Start: uintptr(start),
			End:   uintptr(end),
			Perms: perms,
			Path:  path,
		})
	}
	return regions, scanner.Err()
}
