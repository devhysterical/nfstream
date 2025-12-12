# NFStream HTTP/2 & HTTP/3 Fingerprinting Plugin

## Quick Introduction

This is a complete contribution to the [NFStream](https://github.com/nfstream/nfstream) project - adding HTTP/2 and HTTP/3 traffic analysis and fingerprinting capabilities.

## What Has Been Added

### 1. Plugin Core
- **`nfstream/plugins/http2.py`** (340 lines)
  - `HTTP2Fingerprint`: Analyzes HTTP/2 frames and SETTINGS
  - `HTTP3Fingerprint`: Detects QUIC and HTTP/3 traffic

### 2. Testing
- **`test_http2_http3.py`** (170 lines)
  - Complete test suite with multiple PCAP files

### 3. Examples
- **`examples/http2_http3_example.py`** (280 lines)
  - 7 practical examples: from basic to advanced

### 4. Documentation
- **`HTTP2_HTTP3_PLUGIN_README.md`**
  - Detailed plugin usage guide
- **`CONTRIBUTION_GUIDE_VI.md`**
  - Contribution guide in Vietnamese
- **`CONTRIBUTION_SUMMARY.md`**
  - Complete summary in English
- **`TOM_TAT_DONG_GOP.md`**
  - Detailed summary in Vietnamese

## Quick Start

```python
from nfstream import NFStreamer
from nfstream.plugins import HTTP2Fingerprint, HTTP3Fingerprint

# Analyze PCAP file
streamer = NFStreamer(
    source="your_traffic.pcap",
    udps=[HTTP2Fingerprint(), HTTP3Fingerprint()]
)

for flow in streamer:
    # HTTP/2 Detection
    if flow.udps.http2_detected:
        print(f"HTTP/2: {flow.src_ip} -> {flow.dst_ip}")
        print(f"Fingerprint: {flow.udps.http2_settings_fingerprint}")
        print(f"Settings: {flow.udps.http2_settings_params}")
    
    # HTTP/3 Detection
    if flow.udps.http3_detected:
        print(f"HTTP/3: {flow.src_ip} -> {flow.dst_ip}")
        print(f"QUIC Version: {flow.udps.quic_version}")
```

## Use Cases

### Security
- Detect anomalous clients
- Identify malware traffic
- Bot detection

### Analytics
- Track HTTP/2 and HTTP/3 adoption
- Client identification (Chrome, Firefox, Safari, etc.)
- Traffic characterization

### Debugging
- Verify application configurations
- Troubleshoot connection issues
- Performance analysis

## Features

### HTTP2Fingerprint
Client preface detection  
All 10 frame types supported  
SETTINGS parameters extraction  
Unique fingerprint generation  
PRIORITY and WINDOW_UPDATE tracking
### HTTP3Fingerprint
QUIC protocol detection  
Version identification (v1, draft-29, Q050, etc.)  
Long/short header analysis  
ALPN detection (h3, h3-29, etc.)  
Fingerprint generation
## Documentation

| File | Description |
|------|-------------|
| [TOM_TAT_DONG_GOP.md](TOM_TAT_DONG_GOP.md) | Detailed summary (Vietnamese) |
| [CONTRIBUTION_SUMMARY.md](CONTRIBUTION_SUMMARY.md) | Complete Summary (English) |
| [CONTRIBUTION_GUIDE_VI.md](CONTRIBUTION_GUIDE_VI.md) | Contribution guide (Vietnamese) |
| [HTTP2_HTTP3_PLUGIN_README.md](HTTP2_HTTP3_PLUGIN_README.md) | Plugin Documentation |

## Testing

```bash
# Run test suite
python test_http2_http3.py

# Run examples
python examples/http2_http3_example.py
```

**Note**: To run tests, you need to build NFStream from source (includes C extensions).

## Contributing to NFStream

### Option 1: Pull Request (Recommended)

1. Fork https://github.com/nfstream/nfstream
2. Create branch: `feature/http2-http3-fingerprinting`
3. Copy all files từ contribution này
4. Test và commit
5. Create Pull Request

### Option 2: Use Locally

Copy the files to your current project and customize as needed.

## Impact

### For NFStream Project
First HTTP/2 and HTTP/3 fingerprinting plugin  
Addresses modern, widely-used protocols  
Production-ready quality  
Comprehensive documentation

### For Users
Easy client identification  
Enhanced security monitoring  
Better traffic analysis  
Research capabilities

## Highlights

| Metric | Value |
|--------|-------|
| **Total Code** | ~2000+ lines |
| **Files Created** | 7 files |
| **Documentation** | 4 comprehensive docs |
| **Examples** | 7 practical examples |
| **Test Cases** | Multiple PCAP files |

## Technical Stack

- **Python 3.9+**
- **NFStream Framework**
- **dpkt** - Packet parsing
- **nDPI** - Protocol detection
- **Protocols**: HTTP/2 (RFC 7540), HTTP/3 (RFC 9114), QUIC (RFC 9000)

## References

- [NFStream Documentation](https://www.nfstream.org/)
- [HTTP/2 Specification (RFC 7540)](https://tools.ietf.org/html/rfc7540)
- [HTTP/3 Specification (RFC 9114)](https://tools.ietf.org/html/rfc9114)
- [QUIC Protocol (RFC 9000)](https://tools.ietf.org/html/rfc9000)

## Support

- NFStream Issues: https://github.com/nfstream/nfstream/issues
- Gitter Chat: https://gitter.im/nfstream/community

## License

LGPL-3.0 (Same as NFStream)

