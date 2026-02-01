# CamTRON - Camera Scanner

An automated tool for detecting surveillance devices(cameras) on networks.

## Features

- **Multi-brand detection**: Supports 30+ camera brands including Hikvision, Dahua, Axis, CCTV, and more
- **High-performance scanning**: Concurrent scanning with configurable thread count
- **Flexible input**: Scan single IPs, URLs, CIDR ranges, or files with target lists
- **Smart detection**: Uses multiple detection methods (titles, headers, favicon MD5 hashes, body content)
- **CSV export**: Option to save results to CSV file
- **Real-time progress**: Live progress display with color-coded output
- **Resilient**: Handles network timeouts and malformed responses gracefully

---

## Installation

### Prerequisites

- Go 1.16 or higher

### From Source

```bash
git clone https://github.com/K3ysTr0K3R/camtron.git
cd camtron
go build -o camtron main.go
```

### Quick Install

```bash
go install github.com/K3ysTr0K3R/camtron@latest
```

---

## Usage

### Basic Scanning Tutorials

#### Scan a Single URL
```bash
./camtron -u http://192.168.1.1
```

#### Scan a Single IP
```bash
./camtron -ip 192.168.1.100
```

#### Scan a CIDR Range
```bash
./camtron -ip 192.168.1.0/24
```

#### Scan Targets From a File
```bash
./camtron -f targets.txt
```

#### Increase Thread Count (Default: 50)
```bash
./camtron -f targets.txt -t 100
```

#### Save Results to CSV
```bash
./camtron -f targets.txt -o results.csv
```

#### Append Results to Existing CSV
```bash
./camtron -f targets.txt -o results.csv -append
```

---

## Command Line Options

```
-u string      Scan a single URL
-ip string     Scan a single IP/CIDR
-f string      File with targets (one per line)
-t int         Threads (default: 50)
-o string      Output CSV file (optional)
-append        Append to output CSV instead of overwrite
```

---

## Input File Format

Create a text file with one target per line:

```
192.168.1.1
192.168.1.100
10.0.0.0/24
http://example.com
```

---

## Supported Brands

- Avtech — Login pages and favicon detection
- Axis — Favicon MD5 detection
- CCTV — Multiple detection methods
- Dahua — Multiple patterns and favicon detection
- D-Link DCS — Header-based detection
- DVR — Login page detection
- Geovision — Title-based detection
- Hikvision — Comprehensive detection (headers, titles, body content)
- Instar — Title-based detection
- IP Camera — Header-based detection
- Netwave — Header-based detection
- Nuuo — Title-based detection
- Reecam — Header-based detection
- Tenda — Multiple login page variants
- Uniview — Favicon and logo detection
- Xiongmai — Title-based detection

---

## Detection Methods

CamTRON uses multiple detection techniques:

- **Title Matching**: Checks HTML `<title>` for brand signatures
- **Header Analysis**: Examines HTTP response headers for identifiers
- **Body Content**: Searches HTML body for known strings
- **Favicon Hashing**: MD5 hashing of `favicon.ico`
- **Status Codes**: Detects specific HTTP response patterns

---

## Performance

- Default threads: 50 concurrent scans
- Timeouts: 2-second timeout per request
- Connection pooling: Reuses HTTP connections
- DNS caching: Reduces repeated DNS lookups
- Progress tracking: Real-time scan statistics

---

## Output

### Console Output

```
[15:04:05.123] [+] 192.168.1.100 : hikvision, dahua
[15:04:05.456] [+] 192.168.1.101 : axis
```

### CSV Output

```csv
Target,Brands
192.168.1.100,"hikvision, dahua"
192.168.1.101,"axis"
```

---

## Building from Source

```bash
git clone https://github.com/yourusername/camtron.git
cd camtron
go build -o camtron .
go build -ldflags="-s -w" -o camtron .
```

---

## Dependencies

- Go standard library
- golang.org/x/net/html

```bash
go mod download
```

---

## Development

### Adding New Rules

Add rules to the `rules` slice in `main.go`:

```go
{"brandname", "/path", "condition=value", "", false}
```

### Supported Conditions

- `title=` — HTML title matching
- `body=` — HTML body matching
- `headers=` — HTTP headers matching
- `md5=` — Favicon MD5 matching
- `status_code=` — HTTP status code matching

### Multiple Conditions

```go
{"brand", "/", "title=Login&&body=Camera System", "", false}
```

---

## Legal Disclaimer

This tool is intended for:

- Security professionals testing their own networks
- Authorized penetration testing engagements
- Educational purposes

**WARNING:** Unauthorized scanning of networks you do not own or have permission to test is illegal. Always obtain proper authorization. The developers assume no responsibility for misuse or damage.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push the branch
5. Open a Pull Request

---

## Support

- Check the Issues page
- Open a new issue with detailed information

**Note:** This tool is for legitimate security assessment purposes only.
