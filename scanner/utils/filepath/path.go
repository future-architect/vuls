package filepath

import (
	"slices"
	"strings"
)

type lazybuf struct {
	path       string
	buf        []byte
	w          int
	volAndPath string
	volLen     int
}

func (b *lazybuf) index(i int) byte {
	if b.buf != nil {
		return b.buf[i]
	}
	return b.path[i]
}

func (b *lazybuf) append(c byte) {
	if b.buf == nil {
		if b.w < len(b.path) && b.path[b.w] == c {
			b.w++
			return
		}
		b.buf = make([]byte, len(b.path))
		copy(b.buf, b.path[:b.w])
	}
	b.buf[b.w] = c
	b.w++
}

func (b *lazybuf) prepend(prefix ...byte) {
	b.buf = slices.Insert(b.buf, 0, prefix...)
	b.w += len(prefix)
}

func (b *lazybuf) string() string {
	if b.buf == nil {
		return b.volAndPath[:b.volLen+b.w]
	}
	return b.volAndPath[:b.volLen] + string(b.buf[:b.w])
}

func ToSlash(path string, separator uint8) string {
	if separator == '/' {
		return path
	}
	return replaceStringByte(path, separator, '/')
}

func FromSlash(path string, separator uint8) string {
	if separator == '/' {
		return path
	}
	return replaceStringByte(path, '/', separator)
}

func replaceStringByte(s string, old, new byte) string {
	if strings.IndexByte(s, old) == -1 {
		return s
	}
	n := []byte(s)
	for i := range n {
		if n[i] == old {
			n[i] = new
		}
	}
	return string(n)
}
