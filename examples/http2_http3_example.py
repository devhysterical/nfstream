"""
HTTP/2 and HTTP/3 Fingerprinting Example
==========================================

This example demonstrates how to use the HTTP2Fingerprint and HTTP3Fingerprint plugins
to analyze modern web traffic and extract fingerprinting information.

HTTP/2 and HTTP/3 are the latest versions of the HTTP protocol, and this plugin
helps identify client characteristics based on their protocol usage patterns.
"""

from nfstream import NFStreamer
from nfstream.plugins import HTTP2Fingerprint, HTTP3Fingerprint


def example_basic_http2_detection():
    """Basic example: Detect HTTP/2 traffic"""
    print("=" * 80)
    print("Example 1: Basic HTTP/2 Detection")
    print("=" * 80)

    streamer = NFStreamer(
        source="your_traffic.pcap",  # Replace with your PCAP file
        udps=[HTTP2Fingerprint()],
        n_dissections=20,  # Enable application detection
        statistical_analysis=False,
    )

    for flow in streamer:
        if flow.udps.http2_detected:
            print(f"\nHTTP/2 Flow:")
            print(f"  {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
            print(f"  Application: {flow.application_name}")
            print(f"  Settings Fingerprint: {flow.udps.http2_settings_fingerprint}")
            print(f"  Frame Types: {', '.join(flow.udps.http2_frame_types)}")


def example_http2_settings_analysis():
    """Advanced example: Analyze HTTP/2 SETTINGS parameters"""
    print("\n" + "=" * 80)
    print("Example 2: HTTP/2 SETTINGS Analysis")
    print("=" * 80)

    streamer = NFStreamer(source="your_traffic.pcap", udps=[HTTP2Fingerprint()])

    settings_fingerprints = {}

    for flow in streamer:
        if flow.udps.http2_detected and flow.udps.http2_settings_fingerprint:
            fp = flow.udps.http2_settings_fingerprint

            if fp not in settings_fingerprints:
                settings_fingerprints[fp] = {
                    "count": 0,
                    "params": flow.udps.http2_settings_params,
                    "example_flow": f"{flow.src_ip}:{flow.src_port}",
                }
            settings_fingerprints[fp]["count"] += 1

    print("\nUnique HTTP/2 Client Fingerprints:")
    for fp, data in settings_fingerprints.items():
        print(f"\n  Fingerprint: {fp}")
        print(f"  Occurrences: {data['count']}")
        print(f"  Example: {data['example_flow']}")
        print(f"  Settings:")
        for param_id, value in data["params"].items():
            param_name = HTTP2Fingerprint.SETTINGS_PARAMS.get(
                param_id, f"ID_{param_id}"
            )
            print(f"    {param_name}: {value}")


def example_http3_detection():
    """Example: Detect HTTP/3 (QUIC) traffic"""
    print("\n" + "=" * 80)
    print("Example 3: HTTP/3 Detection")
    print("=" * 80)

    streamer = NFStreamer(
        source="your_traffic.pcap", udps=[HTTP3Fingerprint()], n_dissections=20
    )

    for flow in streamer:
        if flow.udps.http3_detected:
            print(f"\nHTTP/3 Flow:")
            print(f"  {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
            print(f"  QUIC Version: {flow.udps.quic_version}")
            print(f"  Fingerprint: {flow.udps.quic_fingerprint}")
            print(f"  Application: {flow.application_name}")


def example_combined_analysis():
    """Example: Analyze both HTTP/2 and HTTP/3 traffic together"""
    print("\n" + "=" * 80)
    print("Example 4: Combined HTTP/2 and HTTP/3 Analysis")
    print("=" * 80)

    streamer = NFStreamer(
        source="your_traffic.pcap",
        udps=[HTTP2Fingerprint(), HTTP3Fingerprint()],
        n_dissections=20,
        statistical_analysis=True,
    )

    stats = {"total": 0, "http2": 0, "http3": 0, "http2_bytes": 0, "http3_bytes": 0}

    for flow in streamer:
        stats["total"] += 1

        if flow.udps.http2_detected:
            stats["http2"] += 1
            stats["http2_bytes"] += flow.bidirectional_bytes

        if flow.udps.http3_detected:
            stats["http3"] += 1
            stats["http3_bytes"] += flow.bidirectional_bytes

    print(f"\nTraffic Statistics:")
    print(f"  Total Flows: {stats['total']}")
    print(
        f"  HTTP/2 Flows: {stats['http2']} ({stats['http2']/stats['total']*100:.1f}%)"
    )
    print(
        f"  HTTP/3 Flows: {stats['http3']} ({stats['http3']/stats['total']*100:.1f}%)"
    )
    print(f"  HTTP/2 Data: {stats['http2_bytes']:,} bytes")
    print(f"  HTTP/3 Data: {stats['http3_bytes']:,} bytes")


def example_export_to_csv():
    """Example: Export HTTP/2 fingerprints to CSV"""
    print("\n" + "=" * 80)
    print("Example 5: Export to CSV")
    print("=" * 80)

    streamer = NFStreamer(
        source="your_traffic.pcap", udps=[HTTP2Fingerprint(), HTTP3Fingerprint()]
    )

    # Convert to pandas DataFrame
    df = streamer.to_pandas()

    # Filter for HTTP/2 or HTTP/3 flows
    http_modern = df[
        (df["udps.http2_detected"] == True) | (df["udps.http3_detected"] == True)
    ]

    # Select relevant columns
    columns = [
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "application_name",
        "bidirectional_bytes",
        "udps.http2_detected",
        "udps.http2_settings_fingerprint",
        "udps.http3_detected",
        "udps.quic_version",
    ]

    export_df = http_modern[columns]
    export_df.to_csv("http2_http3_analysis.csv", index=False)

    print(f"\n✅ Exported {len(export_df)} flows to http2_http3_analysis.csv")


def example_live_capture():
    """Example: Live capture and analysis"""
    print("\n" + "=" * 80)
    print("Example 6: Live Traffic Analysis")
    print("=" * 80)

    # Replace with your network interface name
    # On Windows: "Wi-Fi" or "Ethernet"
    # On Linux: "eth0" or "wlan0"
    # On macOS: "en0"

    streamer = NFStreamer(
        source="Wi-Fi",  # Your network interface
        udps=[HTTP2Fingerprint(), HTTP3Fingerprint()],
        n_dissections=20,
        snapshot_length=1536,
        idle_timeout=30,
        active_timeout=300,
    )

    print("\n🔴 Starting live capture... (Press Ctrl+C to stop)")
    print("-" * 80)

    try:
        count = 0
        for flow in streamer:
            if flow.udps.http2_detected:
                print(f"\n[HTTP/2] {flow.src_ip} -> {flow.dst_ip}")
                print(f"  App: {flow.application_name}")
                print(f"  FP: {flow.udps.http2_settings_fingerprint}")

            elif flow.udps.http3_detected:
                print(f"\n[HTTP/3] {flow.src_ip} -> {flow.dst_ip}")
                print(f"  QUIC: {flow.udps.quic_version}")

            count += 1
            if count >= 100:  # Stop after 100 flows for demo
                break

    except KeyboardInterrupt:
        print("\n\n⏹️  Capture stopped by user")


def example_client_identification():
    """Example: Identify different client types by fingerprint"""
    print("\n" + "=" * 80)
    print("Example 7: Client Identification")
    print("=" * 80)

    streamer = NFStreamer(source="your_traffic.pcap", udps=[HTTP2Fingerprint()])

    # Known fingerprints for different clients
    known_clients = {"Chrome": [], "Firefox": [], "Safari": [], "Unknown": []}

    for flow in streamer:
        if flow.udps.http2_detected and flow.udps.http2_settings_fingerprint:
            fp = flow.udps.http2_settings_fingerprint

            # Simple heuristic based on SETTINGS parameters
            # (In practice, you'd build a proper database of fingerprints)
            if flow.udps.http2_settings_count == 6:
                known_clients["Chrome"].append(fp)
            elif flow.udps.http2_settings_count == 5:
                known_clients["Firefox"].append(fp)
            elif flow.udps.http2_settings_count == 4:
                known_clients["Safari"].append(fp)
            else:
                known_clients["Unknown"].append(fp)

    print("\nDetected Clients:")
    for client, fps in known_clients.items():
        unique_fps = set(fps)
        print(
            f"  {client}: {len(fps)} connections, {len(unique_fps)} unique fingerprints"
        )


if __name__ == "__main__":
    print(
        """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║             HTTP/2 and HTTP/3 Fingerprinting Examples                        ║
║                     NFStream Plugin Demonstration                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

This script demonstrates various use cases for the HTTP2Fingerprint and 
HTTP3Fingerprint plugins. Uncomment the examples you want to run and replace
'your_traffic.pcap' with an actual PCAP file path.

Available Examples:
  1. Basic HTTP/2 Detection
  2. HTTP/2 SETTINGS Analysis  
  3. HTTP/3 Detection
  4. Combined Analysis
  5. Export to CSV
  6. Live Traffic Capture
  7. Client Identification

Note: Some examples require specific PCAP files with HTTP/2 or HTTP/3 traffic.
You can capture your own traffic or use the test PCAPs in tests/pcaps/.
"""
    )

    # Uncomment the examples you want to run:
    # example_basic_http2_detection()
    # example_http2_settings_analysis()
    # example_http3_detection()
    # example_combined_analysis()
    # example_export_to_csv()
    # example_live_capture()
    # example_client_identification()
