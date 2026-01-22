package sigscan

func scanBytes(buf, pat []byte, wildcard byte) int {
	patlen := len(pat)
	end := len(buf) - patlen

	for i := 0; i <= end; i++ {
		j := 0
		for ; j < patlen; j++ {
			b := pat[j]
			if b != wildcard && buf[i+j] != b {
				break
			}
		}
		if j == patlen {
			return i
		}
	}
	return -1

}
