package sep

import (
	"encoding/binary"
	"net"

	"golang.org/x/crypto/sha3"
)

func gatherAllBroadcastAddresses() ([]string, error) {
	addrs := []string{}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, intf := range interfaces {
		addresses, err := intf.Addrs()
		if err != nil {
			Logger.Warning(err)
			continue
		}

		for _, addr := range addresses {
			if n, ok := addr.(*net.IPNet); ok {
				if n.IP.To4() == nil {
					continue
				}
				if n.IP.IsGlobalUnicast() {
					ip := n.IP.To4()
					tmp := binary.BigEndian.Uint32(ip) | ^binary.BigEndian.Uint32(n.Mask)
					binary.BigEndian.PutUint32(ip, tmp)
					addrs = append(addrs, ip.String())
				}
			}
		}
	}
	return addrs, nil
}

func internalDigest(p []byte) []byte {
	digest := sha3.Sum256(p)
	return digest[:]
}
