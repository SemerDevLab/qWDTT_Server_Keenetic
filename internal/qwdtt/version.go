package qwdtt

import "fmt"

// These values are replaced by the release build with ldflags.
var (
	BuildVersion = "dev"
	BuildRelease = "0"
)

func ServerVersion() string {
	if BuildVersion == "dev" {
		return "dev"
	}
	return fmt.Sprintf("%s-%s", BuildVersion, BuildRelease)
}
