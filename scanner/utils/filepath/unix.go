package filepath

import (
	"strings"
)

const UnixSeparator = '/'

func UnixAbs(wd, path string) string {
	if unixIsAbs(path) {
		return unixClean(path)
	}
	return unixJoin(wd, path)
}

func unixIsAbs(path string) bool {
	return strings.HasPrefix(path, string(UnixSeparator))
}

func unixJoin(elem ...string) string {
	// If there's a bug here, fix the logic in ./path_plan9.go too.
	for i, e := range elem {
		if e != "" {
			return unixClean(strings.Join(elem[i:], string(UnixSeparator)))
		}
	}
	return ""
}

func unixClean(path string) string {
	originalPath := path
	volLen := unixVolumeNameLen(path)
	path = path[volLen:]
	if path == "" {
		if volLen > 1 && unixIsPathSeparator(originalPath[0]) && unixIsPathSeparator(originalPath[1]) {
			// should be UNC
			return FromSlash(originalPath, UnixSeparator)
		}
		return originalPath + "."
	}
	rooted := unixIsPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: volLen}
	r, dotdot := 0, 0
	if rooted {
		out.append(UnixSeparator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case unixIsPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || unixIsPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || unixIsPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !unixIsPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(UnixSeparator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(UnixSeparator)
			}
			// copy element
			for ; r < n && !unixIsPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	unixPostClean(&out) // avoid creating absolute paths on Windows
	return FromSlash(out.string(), UnixSeparator)
}

func unixVolumeNameLen(_ string) int {
	return 0
}

func unixIsPathSeparator(c uint8) bool {
	return UnixSeparator == c
}

func unixPostClean(_ *lazybuf) {}
