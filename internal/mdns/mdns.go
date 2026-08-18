package mdns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Service represents a discovered mDNS service
type Service struct {
	Name     string            `yaml:"name"`
	Port     int               `yaml:"port"`
	Protocol string            `yaml:"protocol"`
	Service  string            `yaml:"service"`
	Hostname string            `yaml:"hostname"`
	IPv4     []string          `yaml:"ipv4,omitempty"`
	IPv6     []string          `yaml:"ipv6,omitempty"`
	TTL      uint32            `yaml:"ttl"`
	Banner   map[string]string `yaml:"banner,omitempty"`
}

// Device represents a device found on the network
type Device struct {
	IP       string              `yaml:"ip"`
	Services map[string]Service  `yaml:"services"`
	Answers  map[string][]string `yaml:"answers"`
}

// Prober handles mDNS probing
type Prober struct {
	Timeout time.Duration
}

// NewProber creates a new mDNS prober
func NewProber(timeout time.Duration) *Prober {
	return &Prober{Timeout: timeout}
}

var commonServices = []string{
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_workstation._tcp.local.",
	"_smb._tcp.local.",
	"_afpovertcp._tcp.local.",
	"_device-info._tcp.local.",
	"_qdiscover._tcp.local.",
	"_ftp._tcp.local.",
	"_ssh._tcp.local.",
	"_sftp-ssh._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_googlecast._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
}

// Probe unicasts mDNS queries to a specific IP
func (p *Prober) Probe(ctx context.Context, targetIP string) (*Device, error) {
	// 1. Try to find all service types on the device
	serviceTypes, err := p.queryServiceTypes(targetIP)

	// If the device doesn't support the service enumeration, fallback to common types
	if err != nil || len(serviceTypes) == 0 {
		serviceTypes = commonServices
	}

	device := &Device{
		IP:       targetIP,
		Services: make(map[string]Service),
		Answers:  make(map[string][]string),
	}

	// 2. For each service type, find instances and their details
	for _, st := range serviceTypes {
		p.queryServiceDetails(targetIP, st, device)
	}

	if len(device.Services) == 0 {
		return nil, nil
	}

	// Add unique PTRs to answers
	ptrSet := make(map[string]bool)
	for _, svc := range device.Services {
		parts := strings.SplitN(svc.Name, ".", 2)
		if len(parts) == 2 {
			ptrSet[parts[1]] = true
		}
	}
	for ptr := range ptrSet {
		device.Answers["PTR"] = append(device.Answers["PTR"], ptr)
	}

	return device, nil
}

func (p *Prober) queryServiceTypes(targetIP string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false

	c := &dns.Client{
		Net:     "udp",
		Timeout: p.Timeout,
	}

	in, _, err := c.Exchange(m, net.JoinHostPort(targetIP, "5353"))
	if err != nil {
		return nil, err
	}

	var types []string
	for _, answer := range in.Answer {
		if ptr, ok := answer.(*dns.PTR); ok {
			types = append(types, ptr.Ptr)
		}
	}
	return types, nil
}

func (p *Prober) queryServiceDetails(targetIP, serviceType string, device *Device) {
	m := new(dns.Msg)
	m.SetQuestion(serviceType, dns.TypePTR)

	c := &dns.Client{
		Net:     "udp",
		Timeout: p.Timeout,
	}

	in, _, err := c.Exchange(m, net.JoinHostPort(targetIP, "5353"))
	if err != nil {
		return
	}

	// For each PTR record (service instance)
	for _, answer := range in.Answer {
		if ptr, ok := answer.(*dns.PTR); ok {
			instanceName := ptr.Ptr
			p.resolveInstance(targetIP, instanceName, device)
		}
	}
}

func (p *Prober) resolveInstance(targetIP, instanceName string, device *Device) {
	// Try multiple record types to ensure we get everything
	types := []uint16{dns.TypeSRV, dns.TypeTXT, dns.TypeA, dns.TypeAAAA}

	svc := Service{
		Name:   instanceName,
		Banner: make(map[string]string),
	}

	for _, t := range types {
		m := new(dns.Msg)
		m.SetQuestion(instanceName, t)
		c := &dns.Client{Net: "udp", Timeout: p.Timeout}
		in, _, err := c.Exchange(m, net.JoinHostPort(targetIP, "5353"))
		if err != nil {
			continue
		}

		records := append(in.Answer, in.Extra...)
		for _, rec := range records {
			p.parseRecord(rec, &svc)
		}
	}

	if svc.Port == 0 && svc.Hostname == "" {
		return // Didn't get enough info
	}

	// Identify protocol/service type from instance name
	// e.g., "slw-nas._http._tcp.local." -> "http", "tcp"
	parts := strings.Split(instanceName, ".")
	if len(parts) >= 3 {
		svc.Service = strings.TrimPrefix(parts[1], "_")
		svc.Protocol = strings.TrimPrefix(parts[2], "_")
	}

	key := fmt.Sprintf("%d/%s %s", svc.Port, svc.Protocol, svc.Service)
	device.Services[key] = svc
}

func (p *Prober) parseRecord(rec dns.RR, svc *Service) {
	switch r := rec.(type) {
	case *dns.SRV:
		svc.Port = int(r.Port)
		svc.Hostname = r.Target
		svc.TTL = r.Hdr.Ttl
	case *dns.TXT:
		for _, txt := range r.Txt {
			parts := strings.SplitN(txt, "=", 2)
			if len(parts) == 2 {
				svc.Banner[parts[0]] = parts[1]
			} else if len(parts) == 1 && parts[0] != "" {
				svc.Banner[parts[0]] = ""
			}
		}
	case *dns.A:
		ip := r.A.String()
		if !contains(svc.IPv4, ip) {
			svc.IPv4 = append(svc.IPv4, ip)
		}
	case *dns.AAAA:
		ip := r.AAAA.String()
		if !contains(svc.IPv6, ip) {
			svc.IPv6 = append(svc.IPv6, ip)
		}
	}
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
