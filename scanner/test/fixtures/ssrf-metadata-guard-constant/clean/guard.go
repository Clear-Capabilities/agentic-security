package guard

import (
	"fmt"
	"net"
)

var blockedMetadataHosts = map[string]struct{}{
	"metadata.google.internal": {},
}

var metadataV4 = net.ParseIP("169.254.169.254")

func CheckTarget(host string) error {
	if _, ok := blockedMetadataHosts[host]; ok {
		return fmt.Errorf("target %q is a metadata host", host)
	}
	if ip := net.ParseIP(host); ip != nil && ip.Equal(metadataV4) {
		return fmt.Errorf("target %q is the metadata address", host)
	}
	return nil
}
