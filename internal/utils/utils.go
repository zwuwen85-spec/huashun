package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIPRange parses an IP range or CIDR into a slice of IPs
func ParseIPRange(input string) ([]net.IP, error) {
	if strings.Contains(input, "/") {
		return parseCIDR(input)
	}
	if strings.Contains(input, "-") {
		return parseDashRange(input)
	}
	ip := net.ParseIP(input)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", input)
	}
	return []net.IP{ip}, nil
}

func parseCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}

	// Remove network and broadcast addresses for /24 or smaller
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func parseDashRange(input string) ([]net.IP, error) {
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", input)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP in range: %s", input)
	}

	var ips []net.IP
	for ip := startIP; !ip.Equal(nextIP(endIP)); incrementIP(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	incrementIP(next)
	return next
}

// ParsePortRange parses a port range string (e.g., "80,443,1000-2000")
func ParsePortRange(input string) ([]int, error) {
	var ports []int
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return nil, err
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}
