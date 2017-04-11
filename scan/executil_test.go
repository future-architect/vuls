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
	"testing"

	"github.com/future-architect/vuls/config"
)

func TestDecorateCmd(t *testing.T) {
	var tests = []struct {
		conf     config.ServerInfo
		cmd      string
		sudo     bool
		expected string
	}{
		// root sudo false
		{
			conf:     config.ServerInfo{User: "root"},
			cmd:      "ls",
			sudo:     false,
			expected: "ls",
		},
		// root sudo true
		{
			conf:     config.ServerInfo{User: "root"},
			cmd:      "ls",
			sudo:     false,
			expected: "ls",
		},
		// non-root sudo false
		{
			conf:     config.ServerInfo{User: "non-roor"},
			cmd:      "ls",
			sudo:     false,
			expected: "ls",
		},
		// non-root sudo true
		{
			conf:     config.ServerInfo{User: "non-roor"},
			cmd:      "ls",
			sudo:     true,
			expected: "sudo -S ls",
		},
		// non-root sudo true
		{
			conf:     config.ServerInfo{User: "non-roor"},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: "sudo -S ls | sudo  grep hoge",
		},
		// -------------docker-------------
		// root sudo false docker
		{
			conf: config.ServerInfo{
				User:       "root",
				Container:  config.Container{ContainerID: "abc"},
				Containers: config.Containers{Type: "docker"},
			},
			cmd:      "ls",
			sudo:     false,
			expected: `docker exec --user 0 abc /bin/bash -c "ls"`,
		},
		// root sudo true docker
		{
			conf: config.ServerInfo{
				User:       "root",
				Container:  config.Container{ContainerID: "abc"},
				Containers: config.Containers{Type: "docker"},
			},
			cmd:      "ls",
			sudo:     true,
			expected: `docker exec --user 0 abc /bin/bash -c "ls"`,
		},
		// non-root sudo false, docker
		{
			conf: config.ServerInfo{
				User:       "non-root",
				Container:  config.Container{ContainerID: "abc"},
				Containers: config.Containers{Type: "docker"},
			},
			cmd:      "ls",
			sudo:     false,
			expected: `docker exec --user 0 abc /bin/bash -c "ls"`,
		},
		// non-root sudo true, docker
		{
			conf: config.ServerInfo{
				User:       "non-root",
				Container:  config.Container{ContainerID: "abc"},
				Containers: config.Containers{Type: "docker"},
			},
			cmd:      "ls",
			sudo:     true,
			expected: `docker exec --user 0 abc /bin/bash -c "ls"`,
		},
		// non-root sudo true, docker
		{
			conf: config.ServerInfo{
				User:       "non-root",
				Container:  config.Container{ContainerID: "abc"},
				Containers: config.Containers{Type: "docker"},
			},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: `docker exec --user 0 abc /bin/bash -c "ls | grep hoge"`,
		},
		// -------------lxd-------------
		// root sudo false lxd
		{
			conf: config.ServerInfo{
				User:       "root",
				Container:  config.Container{ContainerID: "abc", Name: "def"},
				Containers: config.Containers{Type: "lxd"},
			},
			cmd:      "ls",
			sudo:     false,
			expected: `lxc exec def -- /bin/bash -c "ls"`,
		},
		// root sudo true lxd
		{
			conf: config.ServerInfo{
				User:       "root",
				Container:  config.Container{ContainerID: "abc", Name: "def"},
				Containers: config.Containers{Type: "lxd"},
			},
			cmd:      "ls",
			sudo:     true,
			expected: `lxc exec def -- /bin/bash -c "ls"`,
		},
		// non-root sudo false, lxd
		{
			conf: config.ServerInfo{
				User:       "non-root",
				Container:  config.Container{ContainerID: "abc", Name: "def"},
				Containers: config.Containers{Type: "lxd"},
			},
			cmd:      "ls",
			sudo:     false,
			expected: `lxc exec def -- /bin/bash -c "ls"`,
		},
		// non-root sudo true, lxd
		{
			conf: config.ServerInfo{
				User:       "non-root",
				Container:  config.Container{ContainerID: "abc", Name: "def"},
				Containers: config.Containers{Type: "lxd"},
			},
			cmd:      "ls",
			sudo:     true,
			expected: `lxc exec def -- /bin/bash -c "ls"`,
		},
		// non-root sudo true lxd
		{
			conf: config.ServerInfo{
				User:       "non-root",
				Container:  config.Container{ContainerID: "abc", Name: "def"},
				Containers: config.Containers{Type: "lxd"},
			},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: `lxc exec def -- /bin/bash -c "ls | grep hoge"`,
		},
	}

	for _, tt := range tests {
		actual := decorateCmd(tt.conf, tt.cmd, tt.sudo)
		if actual != tt.expected {
			t.Errorf("expected: %s, actual: %s", tt.expected, actual)
		}
	}
}
