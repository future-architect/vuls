// +build !scanner

package gost

import "testing"

func TestDebian_Supported(t *testing.T) {
	type fields struct {
		Base Base
	}
	type args struct {
		major string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "8 is supported",
			args: args{
				major: "8",
			},
			want: true,
		},
		{
			name: "9 is supported",
			args: args{
				major: "9",
			},
			want: true,
		},
		{
			name: "10 is supported",
			args: args{
				major: "10",
			},
			want: true,
		},
		{
			name: "11 is not supported yet",
			args: args{
				major: "11",
			},
			want: false,
		},
		{
			name: "empty string is not supported yet",
			args: args{
				major: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deb := Debian{}
			if got := deb.supported(tt.args.major); got != tt.want {
				t.Errorf("Debian.Supported() = %v, want %v", got, tt.want)
			}
		})
	}
}
