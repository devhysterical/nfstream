"""
Test script for HTTP2 and HTTP3 fingerprint plugins
"""

import sys
import os

# Add parent directory to path to import nfstream
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nfstream import NFStreamer
from nfstream.plugins import HTTP2Fingerprint, HTTP3Fingerprint


def test_http2_fingerprint():
    """Test HTTP2Fingerprint plugin with sample PCAP files"""
    print("=" * 80)
    print("Testing HTTP2Fingerprint Plugin")
    print("=" * 80)

    # Look for HTTP/2 related pcap files
    test_pcaps = [
        "tests/pcaps/chrome.pcap",
        "tests/pcaps/443-chrome.pcap",
        "tests/pcaps/443-firefox.pcap",
        "tests/pcaps/443-curl.pcap",
    ]

    for pcap_file in test_pcaps:
        if not os.path.exists(pcap_file):
            continue

        print(f"\nProcessing: {pcap_file}")
        print("-" * 80)

        try:
            streamer = NFStreamer(
                source=pcap_file,
                udps=[HTTP2Fingerprint()],
                n_dissections=0,  # Disable nDPI for faster processing
                statistical_analysis=False,
            )

            http2_flows = 0
            for flow in streamer:
                if hasattr(flow, "udps") and flow.udps.http2_detected:
                    http2_flows += 1
                    print(f"\nHTTP/2 Flow Detected:")
                    print(f"Source: {flow.src_ip}:{flow.src_port}")
                    print(f"Destination: {flow.dst_ip}:{flow.dst_port}")
                    print(f"Client Preface: {flow.udps.http2_client_preface}")
                    print(f"Frame Types: {', '.join(flow.udps.http2_frame_types[:10])}")
                    print(f"Settings Count: {flow.udps.http2_settings_count}")
                    print(
                        f"Settings Fingerprint: {flow.udps.http2_settings_fingerprint}"
                    )
                    if flow.udps.http2_settings_params:
                        print(f"Settings Parameters:")
                        for param_id, value in list(
                            flow.udps.http2_settings_params.items()
                        )[:5]:
                            param_name = HTTP2Fingerprint.SETTINGS_PARAMS.get(
                                param_id, f"UNKNOWN_{param_id}"
                            )
                            print(f"{param_name}: {value}")
                    if flow.udps.http2_window_update:
                        print(f"Window Update: {flow.udps.http2_window_update}")

            print(f"\nSummary: {http2_flows} HTTP/2 flows detected")

        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")


def test_http3_fingerprint():
    """Test HTTP3Fingerprint plugin with sample PCAP files"""
    print("\n" + "=" * 80)
    print("Testing HTTP3Fingerprint Plugin")
    print("=" * 80)

    # Look for QUIC/HTTP3 related pcap files
    test_pcaps = [
        "tests/pcaps/doq.pcapng",
        "tests/pcaps/doq_adguard.pcapng",
        "tests/pcaps/chrome.pcap",
    ]

    for pcap_file in test_pcaps:
        if not os.path.exists(pcap_file):
            continue

        print(f"\nProcessing: {pcap_file}")
        print("-" * 80)

        try:
            streamer = NFStreamer(
                source=pcap_file,
                udps=[HTTP3Fingerprint()],
                n_dissections=0,
                statistical_analysis=False,
            )

            http3_flows = 0
            for flow in streamer:
                if hasattr(flow, "udps") and flow.udps.http3_detected:
                    http3_flows += 1
                    print(f"\nHTTP/3 Flow Detected:")
                    print(f"Source: {flow.src_ip}:{flow.src_port}")
                    print(f"Destination: {flow.dst_ip}:{flow.dst_port}")
                    print(f"QUIC Version: {flow.udps.quic_version}")
                    print(f"Long Header: {flow.udps.quic_long_header}")
                    print(f"QUIC Fingerprint: {flow.udps.quic_fingerprint}")

            print(f"\nSummary: {http3_flows} HTTP/3 flows detected")

        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")


def test_combined():
    """Test both plugins together"""
    print("\n" + "=" * 80)
    print("Testing Combined HTTP2 and HTTP3 Fingerprinting")
    print("=" * 80)

    test_pcap = "tests/pcaps/chrome.pcap"

    if not os.path.exists(test_pcap):
        print(f"Test PCAP not found: {test_pcap}")
        return

    print(f"\nProcessing: {test_pcap}")
    print("-" * 80)

    try:
        streamer = NFStreamer(
            source=test_pcap,
            udps=[HTTP2Fingerprint(), HTTP3Fingerprint()],
            n_dissections=10,  # Enable nDPI to see protocol detection
            statistical_analysis=False,
        )

        http2_count = 0
        http3_count = 0
        total_flows = 0

        for flow in streamer:
            total_flows += 1
            if hasattr(flow, "udps"):
                if flow.udps.http2_detected:
                    http2_count += 1
                if flow.udps.http3_detected:
                    http3_count += 1

        print(f"\nFinal Statistics:")
        print(f"Total Flows: {total_flows}")
        print(f"HTTP/2 Flows: {http2_count}")
        print(f"HTTP/3 Flows: {http3_count}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()


def main():
    """Run all tests"""
    print("\n" + " " * 20)
    print("HTTP/2 and HTTP/3 Fingerprinting Plugin Test Suite")
    print(" " * 20)

    test_http2_fingerprint()
    test_http3_fingerprint()
    test_combined()

    print("\n" + "=" * 80)
    print("All tests completed!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
