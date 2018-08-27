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
			conf:     config.ServerInfo{User: "non-root"},
			cmd:      "ls",
			sudo:     false,
			expected: "ls",
		},
		// non-root sudo true
		{
			conf:     config.ServerInfo{User: "non-root"},
			cmd:      "ls",
			sudo:     true,
			expected: "sudo -S ls",
		},
		// non-root sudo true
		{
			conf:     config.ServerInfo{User: "non-root"},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: "sudo -S ls | grep hoge",
		},
		// -------------docker-------------
		// root sudo false docker
		{
			conf: config.ServerInfo{
				User:          "root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "docker",
			},
			cmd:      "ls",
			sudo:     false,
			expected: `docker exec --user 0 abc /bin/sh -c 'ls'`,
		},
		// root sudo true docker
		{
			conf: config.ServerInfo{
				User:          "root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "docker",
			},
			cmd:      "ls",
			sudo:     true,
			expected: `docker exec --user 0 abc /bin/sh -c 'ls'`,
		},
		// non-root sudo false, docker
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "docker",
			},
			cmd:      "ls",
			sudo:     false,
			expected: `docker exec --user 0 abc /bin/sh -c 'ls'`,
		},
		// non-root sudo true, docker
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "docker",
			},
			cmd:      "ls",
			sudo:     true,
			expected: `docker exec --user 0 abc /bin/sh -c 'ls'`,
		},
		// non-root sudo true, docker
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "docker",
			},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: `docker exec --user 0 abc /bin/sh -c 'ls | grep hoge'`,
		},
		// -------------lxd-------------
		// root sudo false lxd
		{
			conf: config.ServerInfo{
				User:          "root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxd",
			},
			cmd:      "ls",
			sudo:     false,
			expected: `lxc exec def -- /bin/sh -c 'ls'`,
		},
		// root sudo true lxd
		{
			conf: config.ServerInfo{
				User:          "root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxd",
			},
			cmd:      "ls",
			sudo:     true,
			expected: `lxc exec def -- /bin/sh -c 'ls'`,
		},
		// non-root sudo false, lxd
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxd",
			},
			cmd:      "ls",
			sudo:     false,
			expected: `lxc exec def -- /bin/sh -c 'ls'`,
		},
		// non-root sudo true, lxd
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxd",
			},
			cmd:      "ls",
			sudo:     true,
			expected: `lxc exec def -- /bin/sh -c 'ls'`,
		},
		// non-root sudo true lxd
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxd",
			},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: `lxc exec def -- /bin/sh -c 'ls | grep hoge'`,
		},
		// -------------lxc-------------
		// root sudo false lxc
		{
			conf: config.ServerInfo{
				User:          "root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxc",
			},
			cmd:      "ls",
			sudo:     false,
			expected: `lxc-attach -n def 2>/dev/null -- /bin/sh -c 'ls'`,
		},
		// root sudo true lxc
		{
			conf: config.ServerInfo{
				User:          "root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxc",
			},
			cmd:      "ls",
			sudo:     true,
			expected: `lxc-attach -n def 2>/dev/null -- /bin/sh -c 'ls'`,
		},
		// non-root sudo false, lxc
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxc",
			},
			cmd:      "ls",
			sudo:     false,
			expected: `sudo -S lxc-attach -n def 2>/dev/null -- /bin/sh -c 'ls'`,
		},
		// non-root sudo true, lxc
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxc",
			},
			cmd:      "ls",
			sudo:     true,
			expected: `sudo -S lxc-attach -n def 2>/dev/null -- /bin/sh -c 'ls'`,
		},
		// non-root sudo true lxc
		{
			conf: config.ServerInfo{
				User:          "non-root",
				Container:     config.Container{ContainerID: "abc", Name: "def"},
				ContainerType: "lxc",
			},
			cmd:      "ls | grep hoge",
			sudo:     true,
			expected: `sudo -S lxc-attach -n def 2>/dev/null -- /bin/sh -c 'ls | grep hoge'`,
		},
	}

	for _, tt := range tests {
		actual := decorateCmd(tt.conf, tt.cmd, tt.sudo)
		if actual != tt.expected {
			t.Errorf("expected: %s, actual: %s", tt.expected, actual)
		}
	}
}
