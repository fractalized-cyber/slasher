# Slasher

[![Go Report Card](https://goreportcard.com/badge/github.com/fractalized-cyber/slasher)](https://goreportcard.com/report/github.com/fractalized-cyber/slasher)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)

Slasher is a specialized path traversal vulnerability scanner that tests URLs using various path manipulation techniques. It sends both GET and POST requests with different path variants to identify potential directory traversal vulnerabilities in web applications.

## Features

- Tests multiple path manipulation techniques:
  - Trailing slashes (/)
  - Null bytes (%00)
  - Trailing dots (/.)
  - Double slashes (//)
  - Backslashes (\)
  - URL-encoded slashes (%2f)
  - URL-encoded backslashes (%5c)
  - Double-encoded slashes (%252f)
  - Triple-encoded slashes (%25252f)
- Supports both GET and POST methods
- Handles redirects (optional)
- Processes single URLs or bulk testing from a file
- Automatic retry mechanism for failed requests
- Concurrent scanning for faster results

## Installation

### Prerequisites

- Go 1.21 or later
- Chrome/Chromium browser

### Quick Install

```bash
# Clone the repository
git clone https://github.com/fractalized-cyber/slasher.git
cd slasher

# Install dependencies and build
go mod download
go build

# Run the tool
./slasher -url http://your-target-url
```

### Using Go Install

```bash
go install github.com/fractalized-cyber/slasher@latest
```

## Usage

Basic usage:
```bash
slasher -url http://your-target-url
```

Options:
- `-url`: URL to test or file containing URLs (one per line)
- `-follow`: Follow redirects (default: false)
- `-version`: Show version information

Example:
```bash
slasher -url https://example.com/path/to/test -follow
```

## Output

The tool reports differences in response sizes and status codes that might indicate successful path traversal. Results include:
- Original vs modified URL responses
- Response sizes
- Status codes
- Redirect chains (if any)

## Configuration

The tool uses `patterns.json` for configuring detection patterns. You can modify this file to add or remove patterns:

```json
{
  "patterns": [
    {
      "name": "AWS Access Key",
      "pattern": "\\b(AKIA|ASIA)[A-Z0-9]{16}\\b",
      "description": "AWS Access Key ID"
    },
    // Add more patterns here
  ],
  "ignoredPaths": [
    "performance",
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "webkitStorageInfo",
    "chrome",
    "document",
    "history"
  ],
  "maxDepth": 5
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before testing any systems. 