package scanner

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
