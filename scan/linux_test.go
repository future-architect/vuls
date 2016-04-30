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

package scan

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
)

func TestParseDockerPs(t *testing.T) {

	var test = struct {
		in       string
		expected []config.Container
	}{
		`c7ca0992415a romantic_goldberg
f570ae647edc agitated_lovelace`,
		[]config.Container{
			{
				ContainerID: "c7ca0992415a",
				Name:        "romantic_goldberg",
			},
			{
				ContainerID: "f570ae647edc",
				Name:        "agitated_lovelace",
			},
		},
	}

	r := newRedhat(config.ServerInfo{})
	actual, err := r.parseDockerPs(test.in)
	if err != nil {
		t.Errorf("Error occurred. in: %s, err: %s", test.in, err)
		return
	}
	for i, e := range test.expected {
		if !reflect.DeepEqual(e, actual[i]) {
			t.Errorf("expected %v, actual %v", e, actual[i])
		}
	}
}
