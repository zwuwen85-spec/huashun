# mDNS Asset Mapping Tool

A CLI tool written in Go to map mDNS assets in a given network range.

## Features
- Scan IP ranges (CIDR or dash notation).
- Filter by port ranges.
- Deep banner identification (extracts TXT records, SRV details, etc.).
- Concurrent scanning for high performance.
- Output format compatible with typical network mapping tools.

## Installation
Ensure you have Go installed, then run:
```bash
go mod tidy
go build -o mdns-scan.exe ./cmd/main.go
```

## Usage
```bash
./mdns-scan.exe -i 192.168.1.0/24 -p 80,443,5000-6000
```

### Flags
- `-i, --ip`: IP range to scan (e.g., `192.168.1.0/24` or `192.168.1.1-100`).
- `-p, --port`: Port range to filter (default `0-65535`).
- `-w, --workers`: Number of concurrent workers (default `50`).
- `-t, --timeout`: Timeout per IP in milliseconds (default `2000`).

## Project Structure
- `cmd/`: CLI entry point.
- `internal/mdns/`: mDNS protocol implementation and banner extraction.
- `internal/scanner/`: Concurrency management and scanning logic.
- `internal/utils/`: IP/Port range parsing utilities.
