// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found here:
// https://github.com/golang/go/blob/master/LICENSE

// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package sep

import (
	"net"
	"reflect"
	"testing"
)

func TestSortByRFC6724(t *testing.T) {
	tests := []struct {
		in      []net.IPAddr
		srcs    []net.IP
		want    []net.IPAddr
		reverse bool // also test it starting backwards
	}{
		// Examples from RFC 6724 section 10.2:

		// Prefer matching scope.
		{
			in: []net.IPAddr{
				{IP: net.ParseIP("2001:db8:1::1")},
				{IP: net.ParseIP("198.51.100.121")},
			},
			srcs: []net.IP{
				net.ParseIP("2001:db8:1::2"),
				net.ParseIP("169.254.13.78"),
			},
			want: []net.IPAddr{
				{IP: net.ParseIP("2001:db8:1::1")},
				{IP: net.ParseIP("198.51.100.121")},
			},
			reverse: true,
		},

		// Prefer matching scope.
		{
			in: []net.IPAddr{
				{IP: net.ParseIP("2001:db8:1::1")},
				{IP: net.ParseIP("198.51.100.121")},
			},
			srcs: []net.IP{
				net.ParseIP("fe80::1"),
				net.ParseIP("198.51.100.117"),
			},
			want: []net.IPAddr{
				{IP: net.ParseIP("198.51.100.121")},
				{IP: net.ParseIP("2001:db8:1::1")},
			},
			reverse: true,
		},

		// Prefer higher precedence.
		{
			in: []net.IPAddr{
				{IP: net.ParseIP("2001:db8:1::1")},
				{IP: net.ParseIP("10.1.2.3")},
			},
			srcs: []net.IP{
				net.ParseIP("2001:db8:1::2"),
				net.ParseIP("10.1.2.4"),
			},
			want: []net.IPAddr{
				{IP: net.ParseIP("2001:db8:1::1")},
				{IP: net.ParseIP("10.1.2.3")},
			},
			reverse: true,
		},

		// Prefer smaller scope.
		{
			in: []net.IPAddr{
				{IP: net.ParseIP("2001:db8:1::1")},
				{IP: net.ParseIP("fe80::1")},
			},
			srcs: []net.IP{
				net.ParseIP("2001:db8:1::2"),
				net.ParseIP("fe80::2"),
			},
			want: []net.IPAddr{
				{IP: net.ParseIP("fe80::1")},
				{IP: net.ParseIP("2001:db8:1::1")},
			},
			reverse: true,
		},

		// Issue 13283.  Having a 10/8 source address does not
		// mean we should prefer 23/8 destination addresses.
		{
			in: []net.IPAddr{
				{IP: net.ParseIP("54.83.193.112")},
				{IP: net.ParseIP("184.72.238.214")},
				{IP: net.ParseIP("23.23.172.185")},
				{IP: net.ParseIP("75.101.148.21")},
				{IP: net.ParseIP("23.23.134.56")},
				{IP: net.ParseIP("23.21.50.150")},
			},
			srcs: []net.IP{
				net.ParseIP("10.2.3.4"),
				net.ParseIP("10.2.3.4"),
				net.ParseIP("10.2.3.4"),
				net.ParseIP("10.2.3.4"),
				net.ParseIP("10.2.3.4"),
				net.ParseIP("10.2.3.4"),
			},
			want: []net.IPAddr{
				{IP: net.ParseIP("54.83.193.112")},
				{IP: net.ParseIP("184.72.238.214")},
				{IP: net.ParseIP("23.23.172.185")},
				{IP: net.ParseIP("75.101.148.21")},
				{IP: net.ParseIP("23.23.134.56")},
				{IP: net.ParseIP("23.21.50.150")},
			},
			reverse: false,
		},
	}
	for i, tt := range tests {
		inCopy := make([]net.IPAddr, len(tt.in))
		copy(inCopy, tt.in)
		srcCopy := make([]net.IP, len(tt.in))
		copy(srcCopy, tt.srcs)
		sortByRFC6724withSrcs(inCopy, srcCopy)
		if !reflect.DeepEqual(inCopy, tt.want) {
			t.Errorf("test %d:\nin = %s\ngot: %s\nwant: %s\n", i, tt.in, inCopy, tt.want)
		}
		if tt.reverse {
			copy(inCopy, tt.in)
			copy(srcCopy, tt.srcs)
			for j := 0; j < len(inCopy)/2; j++ {
				k := len(inCopy) - j - 1
				inCopy[j], inCopy[k] = inCopy[k], inCopy[j]
				srcCopy[j], srcCopy[k] = srcCopy[k], srcCopy[j]
			}
			sortByRFC6724withSrcs(inCopy, srcCopy)
			if !reflect.DeepEqual(inCopy, tt.want) {
				t.Errorf("test %d, starting backwards:\nin = %s\ngot: %s\nwant: %s\n", i, tt.in, inCopy, tt.want)
			}
		}

	}

}

func TestRFC6724PolicyTableClassify(t *testing.T) {
	tests := []struct {
		ip   net.IP
		want policyTableEntry
	}{
		{
			ip: net.ParseIP("127.0.0.1"),
			want: policyTableEntry{
				Prefix:     &net.IPNet{IP: net.ParseIP("::ffff:0:0"), Mask: net.CIDRMask(96, 128)},
				Precedence: 35,
				Label:      4,
			},
		},
		{
			ip: net.ParseIP("2601:645:8002:a500:986f:1db8:c836:bd65"),
			want: policyTableEntry{
				Prefix:     &net.IPNet{IP: net.ParseIP("::"), Mask: net.CIDRMask(0, 128)},
				Precedence: 40,
				Label:      1,
			},
		},
		{
			ip: net.ParseIP("::1"),
			want: policyTableEntry{
				Prefix:     &net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
				Precedence: 50,
				Label:      0,
			},
		},
		{
			ip: net.ParseIP("2002::ab12"),
			want: policyTableEntry{
				Prefix:     &net.IPNet{IP: net.ParseIP("2002::"), Mask: net.CIDRMask(16, 128)},
				Precedence: 30,
				Label:      2,
			},
		},
	}
	for i, tt := range tests {
		got := rfc6724policyTable.Classify(tt.ip)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%d. Classify(%s) = %v; want %v", i, tt.ip, got, tt.want)
		}
	}
}

func TestRFC6724ClassifyScope(t *testing.T) {
	tests := []struct {
		ip   net.IP
		want scope
	}{
		{net.ParseIP("127.0.0.1"), scopeLinkLocal},   // rfc6724#section-3.2
		{net.ParseIP("::1"), scopeLinkLocal},         // rfc4007#section-4
		{net.ParseIP("169.254.1.2"), scopeLinkLocal}, // rfc6724#section-3.2
		{net.ParseIP("fec0::1"), scopeSiteLocal},
		{net.ParseIP("8.8.8.8"), scopeGlobal},

		{net.ParseIP("ff02::"), scopeLinkLocal},  // IPv6 multicast
		{net.ParseIP("ff05::"), scopeSiteLocal},  // IPv6 multicast
		{net.ParseIP("ff04::"), scopeAdminLocal}, // IPv6 multicast
		{net.ParseIP("ff0e::"), scopeGlobal},     // IPv6 multicast

		{net.IPv4(0xe0, 0, 0, 0), scopeGlobal},       // IPv4 link-local multicast as 16 bytes
		{net.IPv4(0xe0, 2, 2, 2), scopeGlobal},       // IPv4 global multicast as 16 bytes
		{net.IPv4(0xe0, 0, 0, 0).To4(), scopeGlobal}, // IPv4 link-local multicast as 4 bytes
		{net.IPv4(0xe0, 2, 2, 2).To4(), scopeGlobal}, // IPv4 global multicast as 4 bytes
	}
	for i, tt := range tests {
		got := classifyScope(tt.ip)
		if got != tt.want {
			t.Errorf("%d. classifyScope(%s) = %x; want %x", i, tt.ip, got, tt.want)
		}
	}
}

func TestRFC6724CommonPrefixLength(t *testing.T) {
	tests := []struct {
		a, b net.IP
		want int
	}{
		{net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), 64},
		{net.ParseIP("fe81::1"), net.ParseIP("fe80::2"), 15},
		{net.ParseIP("127.0.0.1"), net.ParseIP("fe80::1"), 0}, // diff size
		{net.IPv4(1, 2, 3, 4), net.IP{1, 2, 3, 4}, 32},
		{net.IP{1, 2, 255, 255}, net.IP{1, 2, 0, 0}, 16},
		{net.IP{1, 2, 127, 255}, net.IP{1, 2, 0, 0}, 17},
		{net.IP{1, 2, 63, 255}, net.IP{1, 2, 0, 0}, 18},
		{net.IP{1, 2, 31, 255}, net.IP{1, 2, 0, 0}, 19},
		{net.IP{1, 2, 15, 255}, net.IP{1, 2, 0, 0}, 20},
		{net.IP{1, 2, 7, 255}, net.IP{1, 2, 0, 0}, 21},
		{net.IP{1, 2, 3, 255}, net.IP{1, 2, 0, 0}, 22},
		{net.IP{1, 2, 1, 255}, net.IP{1, 2, 0, 0}, 23},
		{net.IP{1, 2, 0, 255}, net.IP{1, 2, 0, 0}, 24},
	}
	for i, tt := range tests {
		got := commonPrefixLen(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("%d. commonPrefixLen(%s, %s) = %d; want %d", i, tt.a, tt.b, got, tt.want)
		}
	}

}
