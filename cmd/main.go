package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"huashun-mdns-scan/internal/mdns"
	"huashun-mdns-scan/internal/scanner"
	"huashun-mdns-scan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	ipRange   string
	portRange string
	workers   int
	timeout   int
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "mdns-scan",
		Short: "mDNS asset mapping tool",
		Run:   runScan,
	}

	rootCmd.Flags().StringVarP(&ipRange, "ip", "i", "", "IP range (e.g., 192.168.1.0/24, 192.168.1.1-100)")
	rootCmd.Flags().StringVarP(&portRange, "port", "p", "0-65535", "Port range (e.g., 80,443,5000-6000)")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 50, "Number of concurrent workers")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 2000, "Timeout in milliseconds")

	rootCmd.MarkFlagRequired("ip")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	ips, err := utils.ParseIPRange(ipRange)
	if err != nil {
		fmt.Printf("Error parsing IP range: %v\n", err)
		return
	}

	ports, err := utils.ParsePortRange(portRange)
	if err != nil {
		fmt.Printf("Error parsing port range: %v\n", err)
		return
	}

	s := scanner.NewScanner(ips, ports, workers, time.Duration(timeout)*time.Millisecond)
	results := s.Run(context.Background())

	for _, device := range results {
		printDevice(device)
	}
}

func printDevice(d *mdns.Device) {
	fmt.Printf("# Device: %s\n", d.IP)
	fmt.Println("services:")

	// Sort keys for consistent output
	keys := make([]string, 0, len(d.Services))
	for k := range d.Services {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		svc := d.Services[k]
		fmt.Printf("  %s:\n", k)

		// Instance Name (extracting the prefix)
		nameParts := strings.Split(svc.Name, ".")
		name := nameParts[0]
		fmt.Printf("    Name=%s\n", name)

		if len(svc.IPv4) > 0 {
			fmt.Printf("    IPv4=%s\n", strings.Join(svc.IPv4, ","))
		} else {
			fmt.Printf("    IPv4=%s\n", d.IP) // Fallback to probed IP
		}

		if len(svc.IPv6) > 0 {
			fmt.Printf("    IPv6=%s\n", strings.Join(svc.IPv6, ","))
		}

		hostname := strings.TrimSuffix(svc.Hostname, ".")
		if hostname == "" {
			hostname = name + ".local"
		}
		fmt.Printf("    Hostname=%s\n", hostname)
		fmt.Printf("    TTL=%d\n", svc.TTL)

		// Print Banner details
		bannerKeys := make([]string, 0, len(svc.Banner))
		for bk := range svc.Banner {
			bannerKeys = append(bannerKeys, bk)
		}
		sort.Strings(bannerKeys)
		for _, bk := range bannerKeys {
			val := svc.Banner[bk]
			if val != "" {
				fmt.Printf("    %s=%s\n", bk, val)
			} else {
				fmt.Printf("    %s\n", bk)
			}
		}
	}

	if ptrs, ok := d.Answers["PTR"]; ok && len(ptrs) > 0 {
		fmt.Println("  answers:")
		fmt.Println("    PTR:")
		sort.Strings(ptrs)
		for _, ptr := range ptrs {
			fmt.Printf("      %s\n", ptr)
		}
	}
	fmt.Println()
}
