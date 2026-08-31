#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace delta_nids::capture {

struct CaptureConfig {
    std::string interface_name;
    std::string pcap_path;
    std::string bpf_filter;
    std::size_t snap_length = 65535;
    std::size_t buffer_size = 0;
    int timeout_ms = 1000;
    bool promiscuous = true;
};

struct CapturedPacket {
    std::int64_t seconds = 0;
    std::int32_t nanoseconds = 0;
    std::uint32_t captured_length = 0;
    std::uint32_t original_length = 0;
    std::vector<std::uint8_t> bytes;
};

struct CaptureStatistics {
    std::uint64_t received = 0;
    std::uint64_t delivered = 0;
    std::uint64_t dropped = 0;
    std::uint64_t truncated = 0;
};

using PacketHandler = std::function<void(CapturedPacket)>;

class PacketCapture {
public:
    virtual ~PacketCapture() = default;
    virtual void run(const PacketHandler& handler) = 0;
    virtual void stop() noexcept = 0;
    [[nodiscard]] virtual CaptureStatistics statistics() const noexcept = 0;
};

[[nodiscard]] std::unique_ptr<PacketCapture> make_capture(const CaptureConfig& config);

}  // namespace delta_nids::capture
