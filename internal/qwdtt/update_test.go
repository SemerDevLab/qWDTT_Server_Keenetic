package qwdtt

import "testing"

func TestCompareReleaseVersions(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{"0.1.0-21", "0.1.0-22", -1},
		{"0.1.0-22", "0.1.0-22", 0},
		{"0.2.0-1", "0.1.9-99", 1},
	}
	for _, test := range tests {
		if got := compareReleaseVersions(test.left, test.right); got != test.want {
			t.Fatalf("compareReleaseVersions(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}

func TestReleaseAssetPattern(t *testing.T) {
	match := releaseAssetPattern.FindStringSubmatch("qwdtt_0.1.0-22_aarch64-3.10-kn.ipk")
	if len(match) != 4 || match[1] != "0.1.0" || match[2] != "22" || match[3] != "aarch64-3.10" {
		t.Fatalf("unexpected release asset match: %#v", match)
	}
}
