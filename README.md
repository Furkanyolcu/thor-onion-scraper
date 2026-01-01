# 🔨 Thor Scraper

> Bulk Onion Site Crawler over the Tor Network - Cyber Threat Intelligence Tool

## 📋 Project Description

Thor Scraper is a CTI (Cyber Threat Intelligence) tool built in Go (Golang). It crawls .onion addresses over the Tor network in bulk, saves their content, and produces status reports.

## 🎯 Features

- ✅ Target list support in YAML format
- ✅ Anonymous connection via Tor SOCKS5 proxy
- ✅ IP leak protection
- ✅ Automatic Tor connection verification
- ✅ Fault tolerance (dead sites do not stop the program)
- ✅ HTML content saving
- ✅ Detailed JSON report output
- ✅ Console and file logging

## 📁 Project Structure

```
thor-scraper/
├── main.go
├── go.mod
├── go.sum
├── targets.yaml
├── output/
│   ├── DuckDuckGo_20241231_120000.html
│   ├── BBC_News_20241231_120100.html
│   └── scan_results.json
├── screenshots/
│   ├── DuckDuckGo_20241231_120000.png
│   └── BBC_News_20241231_120100.png
└── logs/
    └── scan_report.log
```

## 🛠️ Installation

### Requirements

1. **Go 1.21+** must be installed
2. **Tor Service** or **Tor Browser** must be running

### Tor Setup

**Windows:**
- Download and run [Tor Browser](https://www.torproject.org/download/)
- Or use the Tor Expert Bundle

**Linux:**
```bash
sudo apt install tor
sudo systemctl start tor
```

### Build the Project

```bash
cd thor-scraper

# Download dependencies
go mod tidy

# Run
go run main.go

# Or build
go build -o thor-scraper.exe main.go
```

## 🚀 Usage

### Basic Usage

```bash
# Use the default targets.yaml file
go run main.go

# Specify a custom target file
go run main.go mytargets.yaml
```

### Target File Format (targets.yaml)

```yaml
# Comment lines start with #

# Plain URL format
- http://example1234567890abcdef.onion

# HTTPS is also supported
- https://securesite1234567890.onion

# Only the domain can be written (http:// is added automatically)
- sitedomain1234567890abcdef.onion
```

## 📊 Outputs

### 1. Console Output

```
===================================================
  THOR SCRAPER - Tor Network Onion Crawler
  Cyber Threat Intelligence Tool
===================================================

[2024-01-15 14:30:00] [INFO] Thor Scraper starting...
[2024-01-15 14:30:00] [INFO] Total 5 URLs found
[2024-01-15 14:30:01] [SUCCESS] Tor connection active! IP: 185.220.101.xxx
[2024-01-15 14:30:02] [INFO] Scanning: http://example.onion
[2024-01-15 14:30:05] [SUCCESS] Scanning: http://example.onion -> SUCCESS (HTTP 200, 12345 bytes)
[2024-01-15 14:30:07] [ERR] Scanning: http://deadsite.onion -> TIMEOUT
```

### 2. JSON Report (scan_results.json)

```json
{
  "start_time": "2024-01-15T14:30:00Z",
  "end_time": "2024-01-15T14:35:00Z",
  "total_urls": 5,
  "success_count": 3,
  "fail_count": 2,
  "results": [
    {
      "url": "http://example.onion",
      "status": "SUCCESS",
      "timestamp": "2024-01-15T14:30:05Z",
      "file_path": "output/example_onion_20240115_143005.html"
    }
  ]
}
```

### 3. HTML Files

HTML content from each successful scan is saved to the `output/` folder:
- `sitename_onion_20240115_143005.html`

## 🔧 Modules

### Module 1: File Reading (Input Handler)
- Read URLs from YAML/text file
- Whitespace cleanup
- Filter comment lines and blank lines

### Module 2: Tor Proxy Management
- SOCKS5 proxy configuration (127.0.0.1:9050/9150)
- HTTP Transport with IP leak protection
- Tor connection verification

### Module 3: Request and Error Handling
- Timeout management (60 seconds)
- Error logging and moving to next URL
- HTTP status code checking

### Module 4: Data Recording
- Save HTML content
- Generate JSON report
- Write log file

## ⚠️ Security Warnings

1. **Tor Service** must be running
2. Tor connection is verified before the program starts
3. DNS leak prevention is active
4. All traffic passes through SOCKS5 proxy

## 📝 Sample Output

```
==========================================
SCAN COMPLETE - SUMMARY REPORT
==========================================
Total URLs: 10
Successful: 7
Failed: 3
Duration: 2m30s
Output folder: output
Detailed report: output/scan_results.json
==========================================
```

## 📚 Libraries Used

- `net/http` - HTTP requests
- `golang.org/x/net/proxy` - SOCKS5 proxy support
- `os`, `bufio` - File operations
- `encoding/json` - JSON handling

## ⚠️ Warning
This project is for educational and research purposes only.
Use it only on websites you own or have explicit permission to scrape.
Respect robots.txt, website terms of service, and data protection laws.


**⚡ Thor Scraper - A Powerful Tool for Cyber Threat Intelligence**
