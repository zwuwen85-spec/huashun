package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	"huashun-mdns-scan/internal/mdns"
)

type Result struct {
	Device *mdns.Device
	Error  error
}

type Scanner struct {
	IPs     []net.IP
	Ports   map[int]bool
	Workers int
	Timeout time.Duration
}

func NewScanner(ips []net.IP, ports []int, workers int, timeout time.Duration) *Scanner {
	portMap := make(map[int]bool)
	for _, p := range ports {
		portMap[p] = true
	}
	return &Scanner{
		IPs:     ips,
		Ports:   portMap,
		Workers: workers,
		Timeout: timeout,
	}
}

func (s *Scanner) Run(ctx context.Context) []*mdns.Device {
	ipChan := make(chan net.IP, len(s.IPs))
	resultChan := make(chan *mdns.Device, len(s.IPs))
	var wg sync.WaitGroup

	prober := mdns.NewProber(s.Timeout)

	// Start workers
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				device, err := prober.Probe(ctx, ip.String())
				if err != nil || device == nil {
					continue
				}

				// Filter services by port range
				filteredServices := make(map[string]mdns.Service)
				for k, svc := range device.Services {
					// Keep if port matches, or if it's a non-port service like device-info (port 0)
					if s.Ports[svc.Port] || svc.Port == 0 || len(s.Ports) == 0 {
						filteredServices[k] = svc
					}
				}

				if len(filteredServices) > 0 {
					device.Services = filteredServices
					resultChan <- device
				}
			}
		}()
	}

	// Feed IPs
	for _, ip := range s.IPs {
		ipChan <- ip
	}
	close(ipChan)

	// Close resultChan when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []*mdns.Device
	for res := range resultChan {
		results = append(results, res)
	}

	return results
}
