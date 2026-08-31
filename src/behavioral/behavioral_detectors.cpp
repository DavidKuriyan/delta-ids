#include "behavioral/behavioral_manager.h"

#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <utility>

namespace delta_nids::behavioral {
namespace {

std::string ip_string(const packet::IpAddress& value) { return value.to_string(); }
std::string protocol_string(packet::TransportProtocol value) {
    switch (value) {
        case packet::TransportProtocol::tcp: return "TCP";
        case packet::TransportProtocol::udp: return "UDP";
        case packet::TransportProtocol::icmp: return "ICMP";
        case packet::TransportProtocol::icmpv6: return "ICMPv6";
        default: return "other";
    }
}

struct Window {
    std::deque<std::int64_t> times;
    void add(std::int64_t now, std::int64_t span) {
        times.push_back(now);
        while (!times.empty() && now - times.front() > span) times.pop_front();
    }
};

class PortScanDetector final : public BehavioralDetector {
public:
    explicit PortScanDetector(BehavioralConfig config) : config_(config) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (!packet.source_port || !packet.destination_port || packet.transport == packet::TransportProtocol::icmp) return;
        // Only count active probes. Established TCP data and ACK/RST replies
        // otherwise make every busy server look like it is being scanned.
        if (packet.transport == packet::TransportProtocol::tcp && packet.tcp) {
            const auto flags = packet.tcp->flags;
            if ((flags & 0x02U) == 0 || (flags & 0x10U) != 0 || (flags & 0x04U) != 0) return;
        }
        // UDP response traffic must not be counted as outbound probes.
        if (packet.transport == packet::TransportProtocol::udp &&
            (*packet.source_port == 53 || *packet.source_port == 67 ||
             *packet.source_port == 68 || *packet.source_port == 123)) return;
        const auto source = ip_string(packet.source);
        const auto destination = ip_string(packet.destination);
        const auto key = source + "|" + destination + "|" + protocol_string(packet.transport);
        auto& state = states_[key];
        if (std::find_if(state.observations.begin(), state.observations.end(),
                         [&](const auto& observation) { return observation.second == *packet.destination_port; }) == state.observations.end())
            state.observations.emplace_back(packet.timestamp_seconds, *packet.destination_port);
        while (!state.observations.empty() &&
               packet.timestamp_seconds - state.observations.front().first > config_.window_seconds)
            state.observations.pop_front();
        std::set<std::uint16_t> ports;
        for (const auto& observation : state.observations) ports.insert(observation.second);
        if (ports.size() < config_.port_scan_threshold) state.emitted = false;
        if (ports.size() >= config_.port_scan_threshold && !state.emitted) {
            state.emitted = true;
            events.push_back({BehavioralType::port_scan, packet.timestamp_seconds, flow.id, source, destination,
                              protocol_string(packet.transport), "possible vertical port scan",
                              "source contacted one destination on " + std::to_string(ports.size()) + " distinct destination ports within the configured window", 85});
        }
    }
    void expire(std::int64_t now) override {
        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (!iterator->second.observations.empty() && now - iterator->second.observations.back().first > config_.window_seconds) iterator = states_.erase(iterator);
            else ++iterator;
        }
    }
    void reset() override { states_.clear(); }
private:
    struct State { std::deque<std::pair<std::int64_t, std::uint16_t>> observations; bool emitted = false; };
    BehavioralConfig config_;
    std::map<std::string, State> states_;
};

class HostSweepDetector final : public BehavioralDetector {
public:
    explicit HostSweepDetector(BehavioralConfig config) : config_(config) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        const auto source = ip_string(packet.source);
        auto& state = states_[source];
        state.times.add(packet.timestamp_seconds, config_.window_seconds);
        state.destinations.insert(ip_string(packet.destination));
        if (state.destinations.size() >= config_.host_sweep_threshold && !state.emitted) {
            state.emitted = true;
            events.push_back({BehavioralType::host_sweep, packet.timestamp_seconds, flow.id, source, ip_string(packet.destination),
                              protocol_string(packet.transport), "possible host sweep",
                              "source contacted " + std::to_string(state.destinations.size()) + " unique hosts within the configured window", 80});
        }
    }
    void expire(std::int64_t now) override {
        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (!iterator->second.times.times.empty() && now - iterator->second.times.times.back() > config_.window_seconds) iterator = states_.erase(iterator);
            else ++iterator;
        }
    }
    void reset() override { states_.clear(); }
private:
    struct State { Window times; std::set<std::string> destinations; bool emitted = false; };
    BehavioralConfig config_;
    std::map<std::string, State> states_;
};

class RepeatedConnectionDetector final : public BehavioralDetector {
public:
    RepeatedConnectionDetector(BehavioralConfig config, BehavioralType type, std::string service)
        : config_(config), type_(type), service_(std::move(service)) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (packet.transport != packet::TransportProtocol::tcp || !packet.tcp) return;
        if (type_ == BehavioralType::brute_force && flow.service != service_) return;
        const bool failed = (packet.tcp->flags & 0x04U) != 0 || (packet.tcp->flags & 0x01U) != 0;
        if (type_ == BehavioralType::brute_force && !failed) return;
        const auto key = ip_string(packet.source) + ":" + ip_string(packet.destination) + ":" + std::to_string(packet.destination_port.value_or(0));
        auto& state = states_[key];
        state.add(packet.timestamp_seconds, config_.window_seconds);
        if (state.times.size() >= (type_ == BehavioralType::brute_force ? config_.brute_force_threshold : config_.connection_flood_threshold) && !state.emitted) {
            state.emitted = true;
            events.push_back({type_, packet.timestamp_seconds, flow.id, ip_string(packet.source), ip_string(packet.destination), "TCP",
                              type_ == BehavioralType::brute_force ? "repeated authentication-like connection failures" : "connection flood pattern",
                              "observed " + std::to_string(state.times.size()) + " qualifying TCP events within the configured window", 75});
        }
    }
    void expire(std::int64_t now) override {
        for (auto iterator = states_.begin(); iterator != states_.end();) {
            if (!iterator->second.times.empty() && now - iterator->second.times.back() > config_.window_seconds) iterator = states_.erase(iterator);
            else ++iterator;
        }
    }
    void reset() override { states_.clear(); }
private:
    struct State : Window { bool emitted = false; };
    BehavioralConfig config_; BehavioralType type_; std::string service_; std::map<std::string, State> states_;
};

class DnsAnomalyDetector final : public BehavioralDetector {
public:
    explicit DnsAnomalyDetector(BehavioralConfig config) : config_(config) {}
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (flow.service != "DNS" || packet.payload.empty()) return;
        auto& state = states_[ip_string(packet.source)];
        state.add(packet.timestamp_seconds, config_.window_seconds);
        if (state.times.size() >= config_.dns_query_threshold && !state.emitted) {
            state.emitted = true;
            events.push_back({BehavioralType::dns_anomaly, packet.timestamp_seconds, flow.id, ip_string(packet.source), ip_string(packet.destination), "UDP",
                              "high DNS query rate", "source generated " + std::to_string(state.times.size()) + " DNS observations within the configured window", 65});
        }
    }
    void expire(std::int64_t now) override { for (auto iterator = states_.begin(); iterator != states_.end();) { if (now - iterator->second.times.back() > config_.window_seconds) iterator = states_.erase(iterator); else ++iterator; } }
    void reset() override { states_.clear(); }
private:
    struct State : Window { bool emitted = false; };
    BehavioralConfig config_; std::map<std::string, State> states_;
};

class TcpAnomalyDetector final : public BehavioralDetector {
public:
    void observe(const packet::Packet& packet, const flow::Flow& flow, std::vector<BehavioralEvent>& events) override {
        if (packet.transport != packet::TransportProtocol::tcp || !packet.tcp) return;
        const auto flags = packet.tcp->flags;
        if ((flags & 0x02U) && (flags & 0x01U)) {
            events.push_back({BehavioralType::tcp_anomaly, packet.timestamp_seconds, flow.id, ip_string(packet.source), ip_string(packet.destination), "TCP",
                              "invalid TCP SYN/FIN combination", "TCP flags contain SYN and FIN simultaneously", 90});
        }
    }
    void expire(std::int64_t) override {}
    void reset() override {}
};

}  // namespace

BehavioralManager::BehavioralManager(BehavioralConfig config) {
    detectors_.push_back(std::make_unique<PortScanDetector>(config));
    detectors_.push_back(std::make_unique<HostSweepDetector>(config));
    detectors_.push_back(std::make_unique<RepeatedConnectionDetector>(config, BehavioralType::brute_force, "SSH"));
    detectors_.push_back(std::make_unique<RepeatedConnectionDetector>(config, BehavioralType::connection_flood, ""));
    detectors_.push_back(std::make_unique<DnsAnomalyDetector>(config));
    detectors_.push_back(std::make_unique<TcpAnomalyDetector>());
}

std::vector<BehavioralEvent> BehavioralManager::observe(const packet::Packet& packet, const flow::Flow& flow) {
    std::vector<BehavioralEvent> events;
    ++metrics_.packets_observed;
    for (const auto& detector : detectors_) detector->observe(packet, flow, events);
    metrics_.events_generated += events.size();
    return events;
}
void BehavioralManager::expire(std::int64_t now) { for (const auto& detector : detectors_) detector->expire(now); }
void BehavioralManager::reset() { for (const auto& detector : detectors_) detector->reset(); }
const BehavioralMetrics& BehavioralManager::metrics() const noexcept { return metrics_; }

const char* behavioral_type_name(BehavioralType type) noexcept {
    switch (type) { case BehavioralType::port_scan: return "port_scan"; case BehavioralType::host_sweep: return "host_sweep"; case BehavioralType::brute_force: return "brute_force"; case BehavioralType::connection_flood: return "connection_flood"; case BehavioralType::dns_anomaly: return "dns_anomaly"; case BehavioralType::tcp_anomaly: return "tcp_anomaly"; }
    return "unknown";
}

}  // namespace delta_nids::behavioral
