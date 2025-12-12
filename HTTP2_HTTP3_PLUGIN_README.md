# HTTP/2 and HTTP/3 Fingerprinting Plugin

## Overview

The HTTP/2 and HTTP/3 fingerprinting plugins provide advanced protocol analysis capabilities for modern web traffic. These plugins extract unique fingerprints from HTTP/2 and HTTP/3 connections that can be used for:

- **Client identification**: Distinguish between different browsers and applications
- **Traffic analysis**: Understand protocol usage patterns in your network
- **Security monitoring**: Detect anomalous protocol behavior
- **Performance optimization**: Analyze HTTP/2 and HTTP/3 adoption

## Features

### HTTP2Fingerprint Plugin

The `HTTP2Fingerprint` plugin analyzes HTTP/2 traffic and extracts:

- **Connection Preface Detection**: Identifies HTTP/2 client preface
- **SETTINGS Frame Analysis**: Extracts and fingerprints SETTINGS parameters
- **Frame Type Tracking**: Monitors frame types used in the connection
- **PRIORITY Frame Analysis**: Captures stream priority information
- **WINDOW_UPDATE Tracking**: Records initial window size updates

#### Flow Attributes

When using the HTTP2Fingerprint plugin, the following attributes are added to each flow:

| Attribute                    | Type | Description                      |
| ---------------------------- | ---- | -------------------------------- |
| `http2_detected`             | bool | Whether HTTP/2 was detected      |
| `http2_client_preface`       | bool | Whether client preface was found |
| `http2_settings_fingerprint` | str  | MD5 hash of SETTINGS parameters  |
| `http2_priority_fingerprint` | str  | MD5 hash of PRIORITY data        |
| `http2_window_update`        | int  | Initial WINDOW_UPDATE value      |
| `http2_settings_count`       | int  | Number of SETTINGS parameters    |
| `http2_frame_types`          | list | List of frame types observed     |
| `http2_settings_params`      | dict | Raw SETTINGS parameters          |

### HTTP3Fingerprint Plugin

The `HTTP3Fingerprint` plugin analyzes HTTP/3 (QUIC) traffic and extracts:

- **QUIC Version Detection**: Identifies QUIC protocol version
- **Header Type Analysis**: Distinguishes long and short headers
- **ALPN Detection**: Identifies h3 protocol negotiation
- **Fingerprint Generation**: Creates unique fingerprints based on QUIC parameters

#### Flow Attributes

| Attribute           | Type | Description                  |
| ------------------- | ---- | ---------------------------- |
| `http3_detected`    | bool | Whether HTTP/3 was detected  |
| `quic_version`      | str  | QUIC version identifier      |
| `quic_fingerprint`  | str  | MD5 hash of QUIC parameters  |
| `quic_long_header`  | bool | Whether long header was used |
| `http3_frame_types` | list | List of HTTP/3 frame types   |

## Installation

The plugins are included in NFStream. Simply import them:

```python
from nfstream import NFStreamer
from nfstream.plugins import HTTP2Fingerprint, HTTP3Fingerprint
```

## Usage Examples

### Basic HTTP/2 Detection

```python
from nfstream import NFStreamer
from nfstream.plugins import HTTP2Fingerprint

# Analyze PCAP file for HTTP/2 traffic
streamer = NFStreamer(
    source="traffic.pcap",
    udps=[HTTP2Fingerprint()]
)

for flow in streamer:
    if flow.udps.http2_detected:
        print(f"HTTP/2 flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
        print(f"Fingerprint: {flow.udps.http2_settings_fingerprint}")
        print(f"Frame types: {flow.udps.http2_frame_types}")
```

### HTTP/3 (QUIC) Detection

```python
from nfstream.plugins import HTTP3Fingerprint

streamer = NFStreamer(
    source="traffic.pcap",
    udps=[HTTP3Fingerprint()]
)

for flow in streamer:
    if flow.udps.http3_detected:
        print(f"HTTP/3 flow detected")
        print(f"QUIC version: {flow.udps.quic_version}")
        print(f"Fingerprint: {flow.udps.quic_fingerprint}")
```

### Combined Analysis

```python
# Analyze both HTTP/2 and HTTP/3 simultaneously
streamer = NFStreamer(
    source="traffic.pcap",
    udps=[HTTP2Fingerprint(), HTTP3Fingerprint()],
    n_dissections=20  # Enable application detection
)

http2_count = 0
http3_count = 0

for flow in streamer:
    if flow.udps.http2_detected:
        http2_count += 1
    if flow.udps.http3_detected:
        http3_count += 1

print(f"HTTP/2 flows: {http2_count}")
print(f"HTTP/3 flows: {http3_count}")
```

### Live Traffic Analysis

```python
# Capture and analyze live traffic
streamer = NFStreamer(
    source="eth0",  # Your network interface
    udps=[HTTP2Fingerprint(), HTTP3Fingerprint()],
    n_dissections=20
)

for flow in streamer:
    if flow.udps.http2_detected:
        print(f"[LIVE] HTTP/2: {flow.application_name}")
        print(f"  Settings: {flow.udps.http2_settings_params}")
```

### Export to CSV

```python
import pandas as pd

streamer = NFStreamer(
    source="traffic.pcap",
    udps=[HTTP2Fingerprint(), HTTP3Fingerprint()]
)

df = streamer.to_pandas()

# Filter for HTTP/2 and HTTP/3 flows
modern_http = df[
    (df['udps.http2_detected'] == True) |
    (df['udps.http3_detected'] == True)
]

# Export to CSV
modern_http.to_csv('http2_http3_analysis.csv', index=False)
```

### Client Fingerprinting

```python
# Collect unique client fingerprints
fingerprints = {}

streamer = NFStreamer(
    source="traffic.pcap",
    udps=[HTTP2Fingerprint()]
)

for flow in streamer:
    if flow.udps.http2_detected and flow.udps.http2_settings_fingerprint:
        fp = flow.udps.http2_settings_fingerprint

        if fp not in fingerprints:
            fingerprints[fp] = {
                'count': 0,
                'settings': flow.udps.http2_settings_params,
                'ips': set()
            }

        fingerprints[fp]['count'] += 1
        fingerprints[fp]['ips'].add(flow.src_ip)

# Analyze unique clients
for fp, data in fingerprints.items():
    print(f"\nFingerprint: {fp}")
    print(f"Connections: {data['count']}")
    print(f"Unique IPs: {len(data['ips'])}")
    print(f"Settings: {data['settings']}")
```

## Understanding HTTP/2 Fingerprints

HTTP/2 clients send a SETTINGS frame during connection establishment with various parameters. Different browsers and applications use different default values, making this useful for identification:

### Common SETTINGS Parameters

| Parameter              | ID   | Description                 | Typical Values                 |
| ---------------------- | ---- | --------------------------- | ------------------------------ |
| HEADER_TABLE_SIZE      | 0x01 | HPACK table size            | 4096 (Firefox), 65536 (Chrome) |
| ENABLE_PUSH            | 0x02 | Server push enabled         | 0 or 1                         |
| MAX_CONCURRENT_STREAMS | 0x03 | Max parallel streams        | 100-1000                       |
| INITIAL_WINDOW_SIZE    | 0x04 | Initial flow control window | 65535 or 6291456               |
| MAX_FRAME_SIZE         | 0x05 | Maximum frame size          | 16384-16777215                 |
| MAX_HEADER_LIST_SIZE   | 0x06 | Maximum header size         | Often unset                    |

### Example Client Fingerprints

**Chrome:**

- Typically sends 6 SETTINGS parameters
- INITIAL_WINDOW_SIZE: 6291456
- ENABLE_PUSH: 0

**Firefox:**

- Typically sends 5 SETTINGS parameters
- INITIAL_WINDOW_SIZE: 65535
- Different HEADER_TABLE_SIZE

**curl:**

- Minimal SETTINGS frame
- Different parameter ordering

## Understanding HTTP/3 Fingerprints

HTTP/3 uses QUIC as transport protocol. The plugin detects:

- **QUIC Versions**: v1, draft-29, Q050, etc.
- **Header Types**: Long header (initial handshake) vs short header
- **ALPN Negotiation**: "h3", "h3-29", etc.

## Use Cases

### 1. Network Security

```python
# Detect unusual HTTP/2 clients
known_fingerprints = {'abc123...', 'def456...'}  # Your baseline

for flow in streamer:
    if flow.udps.http2_detected:
        fp = flow.udps.http2_settings_fingerprint
        if fp not in known_fingerprints:
            print(f"{flow.src_ip} - {fp}")
```

### 2. Protocol Adoption Tracking

```python
# Track HTTP version usage over time
stats = {'http1': 0, 'http2': 0, 'http3': 0}

for flow in streamer:
    if flow.udps.http3_detected:
        stats['http3'] += 1
    elif flow.udps.http2_detected:
        stats['http2'] += 1
    else:
        stats['http1'] += 1

print(f"HTTP/2: {stats['http2']/sum(stats.values())*100:.1f}%")
print(f"HTTP/3: {stats['http3']/sum(stats.values())*100:.1f}%")
```

### 3. Application Identification

```python
# Combine with nDPI for comprehensive analysis
streamer = NFStreamer(
    source="traffic.pcap",
    udps=[HTTP2FingeUnknown client:rprint()],
    n_dissections=20
)

for flow in streamer:
    if flow.udps.http2_detected:
        print(f"App: {flow.application_name}")
        print(f"HTTP/2 Fingerprint: {flow.udps.http2_settings_fingerprint}")
        # Combine application name with fingerprint for precise identification
```

## Performance Considerations

- The plugins analyze only the initial packets of each flow
- Minimal performance impact on overall processing
- Frame analysis stops after detecting key information
- Suitable for both offline and live traffic analysis

## Testing

Run the included test script:

```bash
python test_http2_http3.py
```

See the [examples directory](../examples/http2_http3_example.py) for more detailed usage examples.

## References

- [HTTP/2 Specification (RFC 7540)](https://tools.ietf.org/html/rfc7540)
- [HTTP/3 Specification (RFC 9114)](https://tools.ietf.org/html/rfc9114)
- [QUIC Protocol (RFC 9000)](https://tools.ietf.org/html/rfc9000)

## Contributing

Contributions are welcome! If you find issues or have improvements:

1. Test with various PCAP files
2. Submit issues on GitHub
3. Create pull requests with enhancements

## License

LGPL-3.0 - Same as NFStream
