package reporter

import "testing"

func TestGetNotifyUsers(t *testing.T) {
	var tests = []struct {
		in       []string
		expected string
	}{
		{
			[]string{"@user1", "@user2"},
			"<@user1> <@user2>",
		},
	}

	for _, tt := range tests {
		actual := SlackWriter{}.getNotifyUsers(tt.in)
		if tt.expected != actual {
			t.Errorf("expected %s, actual %s", tt.expected, actual)
		}
	}

}
