package sep

import "net"

var (
	MNDIPv4MulticastAddress = net.ParseIP("224.0.0.251")
	MNDIPv6MulticastAddress = net.ParseIP("ff02::114") // TODO
	MNDPort                 = 7868                     // ASCII: MD (Multicast Discovery)
)
