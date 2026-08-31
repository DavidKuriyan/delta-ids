#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "capture/packet_capture.h"

namespace delta_nids::packet {

enum class AddressFamily { none, ipv4, ipv6 };
enum class DecodeStatus { valid, truncated, malformed, unsupported };
enum class TransportProtocol { none, tcp, udp, icmp, icmpv6, other };

struct IpAddress {
    AddressFamily family = AddressFamily::none;
    std::vector<std::uint8_t> bytes;

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] bool operator==(const IpAddress& other) const noexcept;
};

struct EthernetMetadata {
    std::vector<std::uint8_t> source_mac;
    std::vector<std::uint8_t> destination_mac;
    std::uint16_t ether_type = 0;
};

struct VlanMetadata {
    std::vector<std::uint16_t> identifiers;
};

struct IpMetadata {
    std::uint8_t version = 0;
    std::uint8_t ttl_or_hop_limit = 0;
    std::uint8_t protocol_number = 0;
    std::uint16_t total_length = 0;
    std::uint32_t fragment_offset = 0;
    bool more_fragments = false;
    bool fragmented = false;
};

struct TcpMetadata {
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgement = 0;
    std::uint16_t window = 0;
    std::uint8_t flags = 0;
    std::uint8_t header_length = 0;
};

struct UdpMetadata {
    std::uint16_t length = 0;
};

struct IcmpMetadata {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
};

struct Packet {
    std::int64_t timestamp_seconds = 0;
    std::int32_t timestamp_nanoseconds = 0;
    std::uint32_t capture_length = 0;
    std::uint32_t original_length = 0;
    std::string interface_id;

    EthernetMetadata ethernet;
    VlanMetadata vlan;
    IpMetadata ip;
    TransportProtocol transport = TransportProtocol::none;
    IpAddress source;
    IpAddress destination;
    std::optional<std::uint16_t> source_port;
    std::optional<std::uint16_t> destination_port;
    std::optional<TcpMetadata> tcp;
    std::optional<UdpMetadata> udp;
    std::optional<IcmpMetadata> icmp;
    std::vector<std::uint8_t> payload;
    DecodeStatus status = DecodeStatus::valid;
};

struct DecodeResult {
    std::optional<Packet> packet;
    DecodeStatus status = DecodeStatus::malformed;
    std::string error;
};

[[nodiscard]] DecodeResult decode(const capture::CapturedPacket& captured,
                                  std::string interface_id = {});

}  // namespace delta_nids::packet
