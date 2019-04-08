/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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

import "golang.org/x/xerrors"

// JSONLoader loads configuration
type JSONLoader struct {
}

// Load load the configuration JSON file specified by path arg.
func (c JSONLoader) Load(path, sudoPass, keyPass string) (err error) {
	return xerrors.New("Not implement yet")
}
