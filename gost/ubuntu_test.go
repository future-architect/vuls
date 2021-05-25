package gost

import "testing"

func TestUbuntu_Supported(t *testing.T) {
	type args struct {
		ubuReleaseVer string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "14.04 is supported",
			args: args{
				ubuReleaseVer: "1404",
			},
			want: true,
		},
		{
			name: "16.04 is supported",
			args: args{
				ubuReleaseVer: "1604",
			},
			want: true,
		},
		{
			name: "18.04 is supported",
			args: args{
				ubuReleaseVer: "1804",
			},
			want: true,
		},
		{
			name: "20.04 is supported",
			args: args{
				ubuReleaseVer: "2004",
			},
			want: true,
		},
		{
			name: "20.10 is supported",
			args: args{
				ubuReleaseVer: "2010",
			},
			want: true,
		},
		{
			name: "21.04 is supported",
			args: args{
				ubuReleaseVer: "2104",
			},
			want: true,
		},
		{
			name: "empty string is not supported yet",
			args: args{
				ubuReleaseVer: "",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ubu := Ubuntu{}
			if got := ubu.supported(tt.args.ubuReleaseVer); got != tt.want {
				t.Errorf("Ubuntu.Supported() = %v, want %v", got, tt.want)
			}
		})
	}
}
