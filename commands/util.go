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

package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/howeyc/gopass"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/xerrors"
)

func getPasswd(prompt string) (string, error) {
	for {
		fmt.Print(prompt)
		pass, err := gopass.GetPasswdMasked()
		if err != nil {
			return "", xerrors.New("Failed to read a password")
		}
		if 0 < len(pass) {
			return string(pass), nil
		}
	}

}

func mkdirDotVuls() error {
	home, err := homedir.Dir()
	if err != nil {
		return err
	}
	dotVuls := filepath.Join(home, ".vuls")
	if _, err := os.Stat(dotVuls); os.IsNotExist(err) {
		if err := os.Mkdir(dotVuls, 0700); err != nil {
			return err
		}
	}
	return nil
}
