/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package config

var (
	// Colors has ansi color list
	Colors = []string{
		"\033[32m", // green
		"\033[33m", // yellow
		"\033[36m", // cyan
		"\033[35m", // magenta
		"\033[31m", // red
		"\033[34m", // blue
	}
	// ResetColor is reset color
	ResetColor = "\033[0m"
)
