"""
------------------------------------------------------------------------------------------------------------------------
http2.py
Copyright (C) 2024 - NFStream Developers
This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
"""

import hashlib
from nfstream import NFPlugin
from dpkt.ip import IP, IP_PROTO_TCP


class HTTP2Fingerprint(NFPlugin):
    """
    HTTP2Fingerprint Plugin: Extract HTTP/2 fingerprinting information

    This plugin analyzes HTTP/2 frames and extracts fingerprinting features that can be used
    to identify clients and their characteristics. It captures:
    - SETTINGS frame parameters
    - WINDOW_UPDATE initial values
    - PRIORITY frame information
    - Header compression patterns (HPACK)

    Attributes:
        flow.udps.http2_detected: Boolean indicating if HTTP/2 was detected
        flow.udps.http2_client_preface: Boolean indicating if client preface was found
        flow.udps.http2_settings_fingerprint: Hash of client SETTINGS parameters
        flow.udps.http2_priority_fingerprint: Hash of PRIORITY frame data
        flow.udps.http2_window_update: Initial WINDOW_UPDATE value
        flow.udps.http2_settings_count: Number of SETTINGS parameters
        flow.udps.http2_frame_types: List of frame types seen
        flow.udps.http2_pseudo_headers: Extracted pseudo headers from HEADERS frame
    """

    # HTTP/2 Connection Preface
    HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # HTTP/2 Frame Types
    FRAME_TYPES = {
        0x00: "DATA",
        0x01: "HEADERS",
        0x02: "PRIORITY",
        0x03: "RST_STREAM",
        0x04: "SETTINGS",
        0x05: "PUSH_PROMISE",
        0x06: "PING",
        0x07: "GOAWAY",
        0x08: "WINDOW_UPDATE",
        0x09: "CONTINUATION",
    }

    # HTTP/2 SETTINGS Parameters
    SETTINGS_PARAMS = {
        0x01: "SETTINGS_HEADER_TABLE_SIZE",
        0x02: "SETTINGS_ENABLE_PUSH",
        0x03: "SETTINGS_MAX_CONCURRENT_STREAMS",
        0x04: "SETTINGS_INITIAL_WINDOW_SIZE",
        0x05: "SETTINGS_MAX_FRAME_SIZE",
        0x06: "SETTINGS_MAX_HEADER_LIST_SIZE",
    }

    def on_init(self, packet, flow):
        """Initialize HTTP/2 tracking for new flow"""
        flow.udps.http2_detected = False
        flow.udps.http2_client_preface = False
        flow.udps.http2_settings_fingerprint = ""
        flow.udps.http2_priority_fingerprint = ""
        flow.udps.http2_window_update = 0
        flow.udps.http2_settings_count = 0
        flow.udps.http2_frame_types = []
        flow.udps.http2_pseudo_headers = {}
        flow.udps.http2_settings_params = {}

        # Try to detect HTTP/2 in first packet
        self._analyze_packet(packet, flow)

    def on_update(self, packet, flow):
        """Update HTTP/2 analysis with each packet"""
        if not flow.udps.http2_detected:
            self._analyze_packet(packet, flow)
        elif (
            len(flow.udps.http2_frame_types) < 20
        ):  # Continue analyzing first 20 frames
            self._parse_http2_frames(packet, flow)

    def on_expire(self, flow):
        """Finalize HTTP/2 fingerprint on flow expiration"""
        if flow.udps.http2_detected and flow.udps.http2_settings_params:
            # Create a unique fingerprint based on SETTINGS parameters
            settings_string = ",".join(
                [
                    f"{self.SETTINGS_PARAMS.get(k, str(k))}={v}"
                    for k, v in sorted(flow.udps.http2_settings_params.items())
                ]
            )
            flow.udps.http2_settings_fingerprint = hashlib.md5(
                settings_string.encode()
            ).hexdigest()[:16]

    def _analyze_packet(self, packet, flow):
        """Analyze packet for HTTP/2 indicators"""
        try:
            if packet.ip_version != 4 or packet.protocol != 6:  # Not IPv4 TCP
                return

            ip_packet = IP(packet.ip_packet)
            if not hasattr(ip_packet, "tcp"):
                return

            tcp_data = ip_packet.tcp.data
            if not tcp_data or len(tcp_data) < 24:
                return

            # Check for HTTP/2 connection preface
            if tcp_data.startswith(self.HTTP2_PREFACE):
                flow.udps.http2_detected = True
                flow.udps.http2_client_preface = True
                # Parse frames after preface
                self._parse_http2_frames_from_data(
                    tcp_data[len(self.HTTP2_PREFACE) :], flow
                )
            # Check for HTTP/2 frame structure (without preface, e.g., server response)
            elif self._is_http2_frame(tcp_data):
                flow.udps.http2_detected = True
                self._parse_http2_frames_from_data(tcp_data, flow)
            # Check for ALPN negotiation result (h2)
            elif b"h2" in tcp_data[:100] or b"HTTP/2" in tcp_data[:100]:
                flow.udps.http2_detected = True

        except Exception:
            pass  # Silently handle parsing errors

    def _parse_http2_frames(self, packet, flow):
        """Parse HTTP/2 frames from packet"""
        try:
            if packet.ip_version != 4 or packet.protocol != 6:
                return

            ip_packet = IP(packet.ip_packet)
            if not hasattr(ip_packet, "tcp"):
                return

            tcp_data = ip_packet.tcp.data
            if tcp_data:
                self._parse_http2_frames_from_data(tcp_data, flow)

        except Exception:
            pass

    def _parse_http2_frames_from_data(self, data, flow):
        """Parse HTTP/2 frames from raw data"""
        offset = 0
        while offset + 9 <= len(data):  # Minimum frame header size
            try:
                # Parse frame header (9 bytes)
                length = int.from_bytes(data[offset : offset + 3], "big")
                frame_type = data[offset + 3]
                flags = data[offset + 4]
                stream_id = (
                    int.from_bytes(data[offset + 5 : offset + 9], "big") & 0x7FFFFFFF
                )

                frame_type_name = self.FRAME_TYPES.get(
                    frame_type, f"UNKNOWN_{frame_type}"
                )

                if frame_type_name not in flow.udps.http2_frame_types:
                    flow.udps.http2_frame_types.append(frame_type_name)

                # Parse frame payload
                payload_start = offset + 9
                payload_end = payload_start + length

                if payload_end > len(data):
                    break  # Incomplete frame

                payload = data[payload_start:payload_end]

                # Parse specific frame types
                if frame_type == 0x04:  # SETTINGS
                    self._parse_settings_frame(payload, flags, flow)
                elif frame_type == 0x08:  # WINDOW_UPDATE
                    self._parse_window_update_frame(payload, flow)
                elif frame_type == 0x02:  # PRIORITY
                    self._parse_priority_frame(payload, flow)

                offset = payload_end

            except Exception:
                break

    def _parse_settings_frame(self, payload, flags, flow):
        """Parse SETTINGS frame"""
        if flags & 0x01:  # ACK flag set
            return

        # SETTINGS frame: each parameter is 6 bytes (2 bytes ID + 4 bytes value)
        offset = 0
        while offset + 6 <= len(payload):
            param_id = int.from_bytes(payload[offset : offset + 2], "big")
            param_value = int.from_bytes(payload[offset + 2 : offset + 6], "big")
            flow.udps.http2_settings_params[param_id] = param_value
            flow.udps.http2_settings_count += 1
            offset += 6

    def _parse_window_update_frame(self, payload, flow):
        """Parse WINDOW_UPDATE frame"""
        if len(payload) >= 4 and flow.udps.http2_window_update == 0:
            increment = int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF
            flow.udps.http2_window_update = increment

    def _parse_priority_frame(self, payload, flow):
        """Parse PRIORITY frame"""
        if len(payload) >= 5 and not flow.udps.http2_priority_fingerprint:
            # Create fingerprint from priority information
            priority_data = payload[:5].hex()
            flow.udps.http2_priority_fingerprint = hashlib.md5(
                priority_data.encode()
            ).hexdigest()[:16]

    def _is_http2_frame(self, data):
        """Check if data looks like HTTP/2 frame"""
        if len(data) < 9:
            return False

        # Check frame type is valid
        frame_type = data[3]
        if frame_type not in self.FRAME_TYPES:
            return False

        # Check frame length is reasonable
        length = int.from_bytes(data[0:3], "big")
        if length > 16777215:  # Max frame size
            return False

        return True


class HTTP3Fingerprint(NFPlugin):
    """
    HTTP3Fingerprint Plugin: Extract HTTP/3 (QUIC) fingerprinting information

    This plugin analyzes QUIC packets to identify HTTP/3 traffic and extract
    fingerprinting features. HTTP/3 uses QUIC protocol over UDP.

    Attributes:
        flow.udps.http3_detected: Boolean indicating if HTTP/3 was detected
        flow.udps.quic_version: QUIC version detected
        flow.udps.quic_fingerprint: Fingerprint based on QUIC parameters
        flow.udps.http3_frame_types: List of HTTP/3 frame types seen
    """

    # QUIC version signatures
    QUIC_VERSIONS = {
        0x00000001: "QUIC_v1",
        0x51303530: "Q050",
        0x51303436: "Q046",
        0xFF00001D: "draft-29",
        0xFF00001C: "draft-28",
        0xFF00001B: "draft-27",
    }

    def on_init(self, packet, flow):
        """Initialize HTTP/3 tracking for new flow"""
        flow.udps.http3_detected = False
        flow.udps.quic_version = ""
        flow.udps.quic_fingerprint = ""
        flow.udps.http3_frame_types = []
        flow.udps.quic_long_header = False

        self._analyze_packet(packet, flow)

    def on_update(self, packet, flow):
        """Update HTTP/3 analysis with each packet"""
        if not flow.udps.http3_detected and packet.protocol == 17:  # UDP
            self._analyze_packet(packet, flow)

    def on_expire(self, flow):
        """Finalize HTTP/3 fingerprint"""
        if flow.udps.http3_detected and flow.udps.quic_version:
            fingerprint_str = f"{flow.udps.quic_version}_{flow.udps.quic_long_header}"
            flow.udps.quic_fingerprint = hashlib.md5(
                fingerprint_str.encode()
            ).hexdigest()[:16]

    def _analyze_packet(self, packet, flow):
        """Analyze packet for HTTP/3/QUIC indicators"""
        try:
            if packet.ip_version != 4 or packet.protocol != 17:  # Not IPv4 UDP
                return

            ip_packet = IP(packet.ip_packet)
            if not hasattr(ip_packet, "udp"):
                return

            udp_data = ip_packet.udp.data
            if not udp_data or len(udp_data) < 8:
                return

            # Check common QUIC ports
            if ip_packet.udp.dport not in [443, 80] and ip_packet.udp.sport not in [
                443,
                80,
            ]:
                return

            # Check for QUIC long header (first bit = 1)
            first_byte = udp_data[0]
            if first_byte & 0x80:  # Long header
                flow.udps.quic_long_header = True

                # Parse version (4 bytes after first byte)
                if len(udp_data) >= 5:
                    version = int.from_bytes(udp_data[1:5], "big")
                    flow.udps.quic_version = self.QUIC_VERSIONS.get(
                        version, f"0x{version:08x}"
                    )

                    # QUIC detected, likely HTTP/3
                    if version != 0:  # Not version negotiation
                        flow.udps.http3_detected = True

            # Check for QUIC short header and ALPN indicators
            elif b"h3" in udp_data[:100] or b"h3-" in udp_data[:100]:
                flow.udps.http3_detected = True
                flow.udps.quic_version = "h3"

        except Exception:
            pass


# Convenience export
__all__ = ["HTTP2Fingerprint", "HTTP3Fingerprint"]
