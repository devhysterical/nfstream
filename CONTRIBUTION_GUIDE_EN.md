# HTTP/2 and HTTP/3 Fingerprinting Plugin Contribution Guide

## Overview

This is a guide for contributing the **HTTP2Fingerprint** and **HTTP3Fingerprint** plugins to the NFStream project.

## What Has Been Added

### 1. New Plugin: `http2.py`

**Path:** `nfstream/plugins/http2.py`

This plugin includes 2 classes:

#### HTTP2Fingerprint

- Detects and analyzes HTTP/2 traffic
- Extracts SETTINGS frame parameters
- Creates unique fingerprint for each client
- Tracks frame types (DATA, HEADERS, PRIORITY, SETTINGS, WINDOW_UPDATE, etc.)
- Supports client preface identification

**Added flow attributes:**

- `http2_detected`: Boolean - Whether HTTP/2 was detected
- `http2_client_preface`: Boolean - Whether client preface exists
- `http2_settings_fingerprint`: String - MD5 hash of SETTINGS parameters
- `http2_priority_fingerprint`: String - MD5 hash of PRIORITY data
- `http2_window_update`: Integer - Initial WINDOW_UPDATE value
- `http2_settings_count`: Integer - Number of SETTINGS parameters
- `http2_frame_types`: List - List of frame types
- `http2_settings_params`: Dict - Raw SETTINGS parameters

#### HTTP3Fingerprint

- Detects and analyzes HTTP/3 (QUIC) traffic
- Identifies QUIC version
- Analyzes long/short headers
- Creates fingerprint based on QUIC parameters

**Added flow attributes:**

- `http3_detected`: Boolean - Whether HTTP/3 was detected
- `quic_version`: String - QUIC version identifier
- `quic_fingerprint`: String - MD5 hash of QUIC parameters
- `quic_long_header`: Boolean - Whether long header was used
- `http3_frame_types`: List - List of HTTP/3 frame types

### 2. Test Script: `test_http2_http3.py`

**Path:** `test_http2_http3.py`

Test script for the plugin with available PCAP files:

- Tests HTTP/2 detection
- Tests HTTP/3 detection
- Tests combined analysis
- Displays details about fingerprints and settings

### 3. Examples: `examples/http2_http3_example.py`

**Path:** `examples/http2_http3_example.py`

7 plugin usage examples:

1. Basic HTTP/2 Detection
2. HTTP/2 SETTINGS Analysis
3. HTTP/3 Detection
4. Combined Analysis
5. Export to CSV
6. Live Traffic Capture
7. Client Identification

### 4. Documentation: `HTTP2_HTTP3_PLUGIN_README.md`

**Path:** `HTTP2_HTTP3_PLUGIN_README.md`

Complete documentation about:

- How to use the plugin
- Flow attributes
- Practical examples
- Use cases
- Performance considerations
- References

### 5. Update: `nfstream/plugins/__init__.py`

Added export for 2 new classes:

```python
from .http2 import HTTP2Fingerprint, HTTP3Fingerprint
```

## How to Use

### Installing NFStream from source

```bash
# Clone repository (if not already done)
git clone --recurse-submodules https://github.com/nfstream/nfstream.git
cd nfstream

# Install dependencies (Linux)
sudo apt-get update
sudo apt-get install python3-dev autoconf automake libtool pkg-config flex bison gettext libjson-c-dev
sudo apt-get install libusb-1.0-0-dev libdbus-glib-1-dev libbluetooth-dev libnl-genl-3-dev

# Build and install
python3 -m pip install -r dev_requirements.txt
python3 -m pip install .
```

### Using the plugin

```python
from nfstream import NFStreamer
from nfstream.plugins import HTTP2Fingerprint, HTTP3Fingerprint

# Analyze PCAP file
streamer = NFStreamer(
    source="your_traffic.pcap",
    udps=[HTTP2Fingerprint(), HTTP3Fingerprint()]
)

for flow in streamer:
    if flow.udps.http2_detected:
        print(f"HTTP/2: {flow.src_ip} -> {flow.dst_ip}")
        print(f"Fingerprint: {flow.udps.http2_settings_fingerprint}")

    if flow.udps.http3_detected:
        print(f"HTTP/3: {flow.src_ip} -> {flow.dst_ip}")
        print(f"QUIC Version: {flow.udps.quic_version}")
```

## Testing

### Running test script

```bash
# After successfully building NFStream
python test_http2_http3.py
```

The script will automatically find and analyze PCAP files in the `tests/pcaps/` directory:

- `chrome.pcap`
- `443-chrome.pcap`
- `443-firefox.pcap`
- `443-curl.pcap`
- `doq.pcapng`
- etc.

### Running examples

```bash
cd examples
python http2_http3_example.py
```

## Plugin Benefits

### 1. Security Monitoring

- Detect anomalous clients based on fingerprints
- Track applications using HTTP/2 and HTTP/3
- Detect protocol anomalies

### 2. Traffic Analysis

- Understand HTTP/2 and HTTP/3 adoption rate
- Analyze performance characteristics
- Compare behavior between different browsers/applications

### 3. Client Identification

- Distinguish Chrome, Firefox, Safari, curl, etc.
- Detect automated tools and bots
- Track client versions

### 4. Research and Development

- Provide datasets for ML models
- Analyze protocol evolution
- Benchmark different implementations

## Real-World Use Cases

### 1. Network Security Team

```python
# Detect unusual HTTP/2 clients
baseline_fingerprints = load_baseline()

for flow in streamer:
    if flow.udps.http2_detected:
        fp = flow.udps.http2_settings_fingerprint
        if fp not in baseline_fingerprints:
            alert(f"Unknown client detected: {flow.src_ip}")
```

### 2. Network Operations

```python
# Monitor HTTP version adoption
stats = analyze_http_versions(pcap_files)
generate_report(stats)  # Show migration to HTTP/2 and HTTP/3
```

### 3. Application Development

```python
# Verify your application's HTTP/2 configuration
my_app_flows = filter_by_ip(flows, my_server_ip)
analyze_settings(my_app_flows)  # Check SETTINGS parameters
```

## Technical Details

### HTTP/2 Detection Logic

1. **Client Preface Detection**: Search for magic string `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`
2. **Frame Structure Analysis**: Parse frame headers (24-bit length + 8-bit type + 8-bit flags + 32-bit stream ID)
3. **SETTINGS Frame Parsing**: Extract parameters (HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, etc.)
4. **Fingerprint Generation**: MD5 hash of sorted SETTINGS parameters

### HTTP/3 Detection Logic

1. **Port Check**: Check ports 80, 443 (common QUIC ports)
2. **QUIC Header Detection**: Analyze first byte to determine long/short header
3. **Version Extraction**: Parse 4-byte version field
4. **ALPN Detection**: Search for "h3" in payload

## Contributing Back to NFStream

### Step 1: Fork and Clone

```bash
# Fork repository on GitHub
# Clone your fork
git clone --recurse-submodules https://github.com/YOUR_USERNAME/nfstream.git
cd nfstream
```

### Step 2: Create Branch

```bash
git checkout -b feature/http2-http3-fingerprinting
```

### Step 3: Copy files

Copy the following files to your fork:

- `nfstream/plugins/http2.py`
- `test_http2_http3.py`
- `examples/http2_http3_example.py`
- `HTTP2_HTTP3_PLUGIN_README.md`
- Update `nfstream/plugins/__init__.py`

### Step 4: Test

```bash
# Build NFStream
python3 -m pip install -r dev_requirements.txt
python3 -m pip install .

# Run existing tests
python3 tests.py

# Run new tests
python3 test_http2_http3.py
```

### Step 5: Commit and Push

```bash
git add .
git commit -m "Add HTTP/2 and HTTP/3 fingerprinting plugins

- Add HTTP2Fingerprint plugin for HTTP/2 analysis
- Add HTTP3Fingerprint plugin for QUIC/HTTP3 analysis
- Add comprehensive tests and examples
- Add detailed documentation
- Update plugins __init__.py to export new classes"

git push origin feature/http2-http3-fingerprinting
```

### Step 6: Create Pull Request

1. Visit your GitHub repository
2. Click "New Pull Request"
3. Select branch `feature/http2-http3-fingerprinting`
4. Write detailed description:

```markdown
## HTTP/2 and HTTP/3 Fingerprinting Plugins

### Summary

This PR adds two new plugins for analyzing modern web traffic:

- `HTTP2Fingerprint`: Analyzes HTTP/2 frames and extracts client fingerprints
- `HTTP3Fingerprint`: Detects and fingerprints HTTP/3 (QUIC) traffic

### Features

- HTTP/2 SETTINGS frame analysis
- Client fingerprint generation based on protocol parameters
- HTTP/3 (QUIC) version detection
- Comprehensive frame type tracking
- Support for both offline and live analysis

### Testing

- Tested with multiple PCAP files (Chrome, Firefox, curl)
- Example scripts provided
- Comprehensive documentation included

### Use Cases

- Client identification and tracking
- Security monitoring
- Protocol adoption analysis
- Network traffic characterization

### Files Added

- `nfstream/plugins/http2.py`: Main plugin implementation
- `test_http2_http3.py`: Test suite
- `examples/http2_http3_example.py`: Usage examples
- `HTTP2_HTTP3_PLUGIN_README.md`: Documentation

### Files Modified

- `nfstream/plugins/__init__.py`: Export new plugins
```

## Checklist before submitting PR

- [ ] Code is properly formatted (PEP 8)
- [ ] Complete docstrings
- [ ] Tests pass successfully
- [ ] Examples run correctly
- [ ] Complete documentation
- [ ] No breaking changes
- [ ] License headers added to new files
- [ ] Clear code comments

## Learning from this plugin

### NFPlugin Architecture

```python
class MyPlugin(NFPlugin):
    def on_init(self, packet, flow):
        # Initialize flow attributes
        flow.udps.my_attribute = initial_value

    def on_update(self, packet, flow):
        # Update with each packet
        flow.udps.my_attribute += 1

    def on_expire(self, flow):
        # Finalize when flow ends
        flow.udps.final_value = compute_final()
```

### Packet Parsing with dpkt

```python
from dpkt.ip import IP

ip_packet = IP(packet.ip_packet)
if hasattr(ip_packet, 'tcp'):
    tcp_data = ip_packet.tcp.data
    # Parse TCP data
```

### Best Practices

1. **Error Handling**: Always wrap parsing logic in try-except
2. **Performance**: Only parse necessary packets (e.g., first N packets)
3. **Memory**: Don't store too much data in flow.udps
4. **Validation**: Check packet structure before parsing

## Future Enhancements

Some ideas for future versions:

1. **Extended HTTP/2 Features**

   - Parse HEADERS frame to extract HTTP headers
   - Analyze PRIORITY tree structure
   - Track PUSH_PROMISE frames

2. **HTTP/3 Enhancements**

   - Parse HTTP/3 frames (HEADERS, DATA, SETTINGS)
   - Extract QPACK compression details
   - Analyze 0-RTT usage

3. **Machine Learning Integration**

   - Train models to classify clients based on fingerprints
   - Anomaly detection for unusual protocol usage
   - Traffic prediction

4. **Performance Optimization**
   - Optimize frame parsing
   - Reduce memory footprint
   - Add caching for repeated fingerprints

## References

- [HTTP/2 RFC 7540](https://tools.ietf.org/html/rfc7540)
- [HTTP/3 RFC 9114](https://tools.ietf.org/html/rfc9114)
- [QUIC RFC 9000](https://tools.ietf.org/html/rfc9000)
- [NFStream Documentation](https://www.nfstream.org/docs)
- [dpkt Documentation](https://dpkt.readthedocs.io/)

## Contact

If you have questions or need support:

- GitHub Issues: https://github.com/nfstream/nfstream/issues
- Gitter Chat: https://gitter.im/nfstream/community
