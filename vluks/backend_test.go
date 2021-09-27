package vluks

import (
	"testing"
)

func TestCrypttabParser(t *testing.T) {
	devices := parseCrypttab(`
		encdev1 /dev/sda none
		encdev2 /dev/sdb /etc/cryptkey
		encdev3 /dev/sdc
		# a comment
		encdev4 /dev/sdd /etc/cryptkey options=key
		# encdev5 /dev/sde /etc/notavalidkey not=valid
	`)
	for _, device := range devices {
		if device[0] == "" {
			t.Fatal(device)
		}
		if device[1] == "" {
			t.Fatal(device)
		}
		if !(device[2] == "" || device[2] == "none" || device[2] == "/etc/cryptkey") {
			t.Fatal()
		}
		if !(device[3] == "" || device[3] == "options=key") {
			t.Fatal()
		}
	}
}
