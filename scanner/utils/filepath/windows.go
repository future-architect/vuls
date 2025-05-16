package filepath

import "strings"

const WindowsSeparator = '\\' // OS-specific path separator

func WindowsAbs(wd, path string) string {
	if windowsIsAbs(path) {
		return windowsClean(path)
	}
	return windowsJoin(wd, path)
}

func windowsIsAbs(path string) bool {
	l := windowsVolumeNameLen(path)
	if l == 0 {
		return false
	}
	// If the volume name starts with a double slash, this is an absolute path.
	if windowsIsPathSeparator(path[0]) && windowsIsPathSeparator(path[1]) {
		return true
	}
	path = path[l:]
	if path == "" {
		return false
	}
	return windowsIsPathSeparator(path[0])
}

func windowsJoin(elem ...string) string {
	var b strings.Builder
	var lastChar byte
	for _, e := range elem {
		switch {
		case b.Len() == 0:
			// Add the first non-empty path element unchanged.
		case windowsIsPathSeparator(lastChar):
			// If the path ends in a slash, strip any leading slashes from the next
			// path element to avoid creating a UNC path (any path starting with "\\")
			// from non-UNC elements.
			//
			// The correct behavior for Join when the first element is an incomplete UNC
			// path (for example, "\\") is underspecified. We currently join subsequent
			// elements so Join("\\", "host", "share") produces "\\host\share".
			for len(e) > 0 && windowsIsPathSeparator(e[0]) {
				e = e[1:]
			}
			// If the path is \ and the next path element is ??,
			// add an extra .\ to create \.\?? rather than \??\
			// (a Root Local Device path).
			if b.Len() == 1 && strings.HasPrefix(e, "??") && (len(e) == len("??") || windowsIsPathSeparator(e[2])) {
				b.WriteString(`.\`)
			}
		case lastChar == ':':
			// If the path ends in a colon, keep the path relative to the current directory
			// on a drive and don't add a separator. Preserve leading slashes in the next
			// path element, which may make the path absolute.
			//
			// 	Join(`C:`, `f`) = `C:f`
			//	Join(`C:`, `\f`) = `C:\f`
		default:
			// In all other cases, add a separator between elements.
			b.WriteByte('\\')
			lastChar = '\\'
		}
		if len(e) > 0 {
			b.WriteString(e)
			lastChar = e[len(e)-1]
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return windowsClean(b.String())
}

func windowsClean(path string) string {
	originalPath := path
	volLen := windowsVolumeNameLen(path)
	path = path[volLen:]
	if path == "" {
		if volLen > 1 && windowsIsPathSeparator(originalPath[0]) && windowsIsPathSeparator(originalPath[1]) {
			// should be UNC
			return FromSlash(originalPath, WindowsSeparator)
		}
		return originalPath + "."
	}
	rooted := windowsIsPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: volLen}
	r, dotdot := 0, 0
	if rooted {
		out.append(WindowsSeparator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case windowsIsPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || windowsIsPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || windowsIsPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !windowsIsPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(WindowsSeparator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(WindowsSeparator)
			}
			// copy element
			for ; r < n && !windowsIsPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	windowsPostClean(&out) // avoid creating absolute paths on Windows
	return FromSlash(out.string(), WindowsSeparator)
}

func windowsVolumeNameLen(path string) int {
	switch {
	case len(path) >= 2 && path[1] == ':':
		// Path starts with a drive letter.
		//
		// Not all Windows functions necessarily enforce the requirement that
		// drive letters be in the set A-Z, and we don't try to here.
		//
		// We don't handle the case of a path starting with a non-ASCII character,
		// in which case the "drive letter" might be multiple bytes long.
		return 2

	case len(path) == 0 || !windowsIsPathSeparator(path[0]):
		// Path does not have a volume component.
		return 0

	case pathHasPrefixFold(path, `\\.\UNC`):
		// We're going to treat the UNC host and share as part of the volume
		// prefix for historical reasons, but this isn't really principled;
		// Windows's own GetFullPathName will happily remove the first
		// component of the path in this space, converting
		// \\.\unc\a\b\..\c into \\.\unc\a\c.
		return uncLen(path, len(`\\.\UNC\`))

	case pathHasPrefixFold(path, `\\.`) ||
		pathHasPrefixFold(path, `\\?`) || pathHasPrefixFold(path, `\??`):
		// Path starts with \\.\, and is a Local Device path; or
		// path starts with \\?\ or \??\ and is a Root Local Device path.
		//
		// We treat the next component after the \\.\ prefix as
		// part of the volume name, which means Clean(`\\?\c:\`)
		// won't remove the trailing \. (See #64028.)
		if len(path) == 3 {
			return 3 // exactly \\.
		}
		_, rest, ok := cutPath(path[4:])
		if !ok {
			return len(path)
		}
		return len(path) - len(rest) - 1

	case len(path) >= 2 && windowsIsPathSeparator(path[1]):
		// Path starts with \\, and is a UNC path.
		return uncLen(path, 2)
	}
	return 0
}

func pathHasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if windowsIsPathSeparator(prefix[i]) {
			if !windowsIsPathSeparator(s[i]) {
				return false
			}
		} else if toUpper(prefix[i]) != toUpper(s[i]) {
			return false
		}
	}
	if len(s) > len(prefix) && !windowsIsPathSeparator(s[len(prefix)]) {
		return false
	}
	return true
}

func toUpper(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func uncLen(path string, prefixLen int) int {
	count := 0
	for i := prefixLen; i < len(path); i++ {
		if windowsIsPathSeparator(path[i]) {
			count++
			if count == 2 {
				return i
			}
		}
	}
	return len(path)
}

func cutPath(path string) (before, after string, found bool) {
	for i := range path {
		if windowsIsPathSeparator(path[i]) {
			return path[:i], path[i+1:], true
		}
	}
	return path, "", false
}

func windowsIsPathSeparator(c uint8) bool {
	return c == '\\' || c == '/'
}

func windowsPostClean(out *lazybuf) {
	if out.volLen != 0 || out.buf == nil {
		return
	}
	// If a ':' appears in the path element at the start of a path,
	// insert a .\ at the beginning to avoid converting relative paths
	// like a/../c: into c:.
	for _, c := range out.buf {
		if windowsIsPathSeparator(c) {
			break
		}
		if c == ':' {
			out.prepend('.', WindowsSeparator)
			return
		}
	}
	// If a path begins with \??\, insert a \. at the beginning
	// to avoid converting paths like \a\..\??\c:\x into \??\c:\x
	// (equivalent to c:\x).
	if len(out.buf) >= 3 && windowsIsPathSeparator(out.buf[0]) && out.buf[1] == '?' && out.buf[2] == '?' {
		out.prepend(WindowsSeparator, '.')
	}
}
