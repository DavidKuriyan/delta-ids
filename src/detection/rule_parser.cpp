#include "detection/rule.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <set>
#include <stdexcept>

namespace delta_nids::detection {
namespace {
using json = nlohmann::json;

void error(RuleLoadResult& result, std::size_t index, const char* field, const std::string& message) {
    result.errors.push_back({index, field, message});
}

std::optional<PortRange> parse_port(const json& value, RuleLoadResult& result, std::size_t index, const char* field) {
    if (value.is_string() && value.get<std::string>() == "any") return std::nullopt;
    if (value.is_number_unsigned()) {
        const auto port = value.get<unsigned>();
        if (port <= 65535) return PortRange{static_cast<std::uint16_t>(port), static_cast<std::uint16_t>(port)};
    }
    if (value.is_string()) {
        const auto text = value.get<std::string>();
        const auto separator = text.find(':');
        try {
            if (separator == std::string::npos) {
                const auto port = std::stoul(text);
                if (port <= 65535) return PortRange{static_cast<std::uint16_t>(port), static_cast<std::uint16_t>(port)};
            } else {
                const auto first = separator == 0 ? 0UL : std::stoul(text.substr(0, separator));
                const auto last = separator + 1 == text.size() ? 65535UL : std::stoul(text.substr(separator + 1));
                if (first <= last && last <= 65535) return PortRange{static_cast<std::uint16_t>(first), static_cast<std::uint16_t>(last)};
            }
        } catch (const std::exception&) {}
    }
    error(result, index, field, "expected 'any', a port, or a port range");
    return std::nullopt;
}

packet::TransportProtocol protocol_from(const std::string& value) {
    if (value == "TCP") return packet::TransportProtocol::tcp;
    if (value == "UDP") return packet::TransportProtocol::udp;
    if (value == "ICMP") return packet::TransportProtocol::icmp;
    if (value == "ICMPV6") return packet::TransportProtocol::icmpv6;
    return packet::TransportProtocol::none;
}

BufferName buffer_from(const std::string& value, bool& known) {
    for (int index = static_cast<int>(BufferName::raw_packet); index <= static_cast<int>(BufferName::tls_handshake); ++index) {
        const auto candidate = static_cast<BufferName>(index);
        if (value == buffer_name(candidate)) return candidate;
    }
    known = false;
    return BufferName::payload;
}

RuleSeverity severity_from(const std::string& value, bool& known) {
    if (value == "INFO") return RuleSeverity::info;
    if (value == "LOW") return RuleSeverity::low;
    if (value == "MEDIUM") return RuleSeverity::medium;
    if (value == "HIGH") return RuleSeverity::high;
    if (value == "CRITICAL") return RuleSeverity::critical;
    known = false;
    return RuleSeverity::medium;
}

}  // namespace

RuleLoadResult load_rules(const std::string& path) {
    RuleLoadResult result;
    std::ifstream stream(path);
    if (!stream) {
        result.errors.push_back({0, "file", "unable to open rule file: " + path});
        return result;
    }
    json document;
    try { stream >> document; }
    catch (const json::exception& exception) {
        result.errors.push_back({0, "file", exception.what()});
        return result;
    }
    if (!document.is_array()) {
        result.errors.push_back({0, "root", "rule file must contain a JSON array"});
        return result;
    }

    std::set<std::pair<std::uint32_t, std::uint32_t>> identities;
    for (std::size_t index = 0; index < document.size(); ++index) {
        const auto& item = document[index];
        if (!item.is_object()) {
            error(result, index, "rule", "rule must be an object");
            continue;
        }
        Rule rule;
        rule.source_file = path;
        if (!item.contains("sid") || !item["sid"].is_number_unsigned() || item["sid"].get<unsigned>() == 0) {
            error(result, index, "sid", "sid must be a positive integer");
            continue;
        }
        rule.sid = item["sid"].get<std::uint32_t>();
        if (item.contains("gid")) {
            if (!item["gid"].is_number_unsigned() || item["gid"].get<unsigned>() == 0) error(result, index, "gid", "gid must be a positive integer");
            else rule.gid = item["gid"].get<std::uint32_t>();
        }
        if (item.contains("rev")) {
            if (!item["rev"].is_number_unsigned() || item["rev"].get<unsigned>() == 0) error(result, index, "rev", "rev must be a positive integer");
            else rule.revision = item["rev"].get<std::uint32_t>();
        }
        if (!identities.insert({rule.sid, rule.revision}).second) error(result, index, "sid", "duplicate sid/revision");

        const auto action = item.value("action", "ALERT");
        if (action == "ALERT") rule.action = RuleAction::alert;
        else if (action == "LOG") rule.action = RuleAction::log;
        else error(result, index, "action", "only ALERT and LOG are supported in passive mode");

        const auto protocol = item.value("protocol", "TCP");
        rule.protocol = protocol_from(protocol);
        if (rule.protocol == packet::TransportProtocol::none) error(result, index, "protocol", "unsupported protocol");
        if (item.contains("src_port")) rule.source_port = parse_port(item["src_port"], result, index, "src_port");
        if (item.contains("dst_port")) rule.destination_port = parse_port(item["dst_port"], result, index, "dst_port");
        const auto direction = item.value("direction", "any");
        if (direction == "client_to_server") rule.direction = RuleDirection::client_to_server;
        else if (direction == "server_to_client") rule.direction = RuleDirection::server_to_client;
        else if (direction != "any") error(result, index, "direction", "unsupported direction");

        if (item.contains("service")) {
            const auto service_text = item["service"].get<std::string>();
            for (int value = static_cast<int>(protocol::Service::unknown); value <= static_cast<int>(protocol::Service::generic_udp); ++value) {
                const auto service = static_cast<protocol::Service>(value);
                if (service_text == protocol::service_name(service)) rule.service = service;
            }
            if (!rule.service) error(result, index, "service", "unsupported service");
        }
        if (item.contains("buffer")) {
            bool known = true;
            rule.buffer = buffer_from(item["buffer"].get<std::string>(), known);
            if (!known) error(result, index, "buffer", "unsupported detection buffer");
        }
        if (item.contains("content")) {
            if (item["content"].is_string()) {
                const auto text = item["content"].get<std::string>();
                rule.content.assign(text.begin(), text.end());
                rule.content_chain.push_back(rule.content);
            } else if (item["content"].is_array()) {
                for (const auto& value : item["content"]) {
                    if (!value.is_string()) { error(result, index, "content", "content chain entries must be strings"); break; }
                    const auto text = value.get<std::string>();
                    rule.content_chain.emplace_back(text.begin(), text.end());
                }
                if (!rule.content_chain.empty()) rule.content = rule.content_chain.front();
            } else error(result, index, "content", "content must be a string or string array");
        }
        const auto allowed = std::set<std::string>{"gid", "sid", "rev", "action", "protocol", "src_port", "dst_port", "direction", "service", "buffer", "content", "nocase", "offset", "depth", "distance", "within", "message", "classification", "priority", "severity", "suppression_key", "threshold"};
        for (const auto& entry : item.items())
            if (!allowed.count(entry.key())) error(result, index, entry.key().c_str(), "unsupported rule field");
        rule.nocase = item.value("nocase", false);
        if (item.contains("nocase") && !item["nocase"].is_boolean()) error(result, index, "nocase", "nocase must be boolean");
        if (item.contains("offset")) {
            if (!item["offset"].is_number_unsigned()) error(result, index, "offset", "offset must be non-negative integer");
            else rule.offset = item["offset"].get<std::size_t>();
        }
        if (item.contains("depth")) {
            if (!item["depth"].is_number_unsigned()) error(result, index, "depth", "depth must be non-negative integer");
            else rule.depth = item["depth"].get<std::size_t>();
        }
        if (item.contains("distance")) {
            if (!item["distance"].is_number_unsigned()) error(result, index, "distance", "distance must be non-negative integer");
            else rule.distance = item["distance"].get<std::size_t>();
        }
        if (item.contains("within")) {
            if (!item["within"].is_number_unsigned()) error(result, index, "within", "within must be non-negative integer");
            else rule.within = item["within"].get<std::size_t>();
        }
        rule.message = item.value("message", "Delta-NIDS rule " + std::to_string(rule.sid));
        rule.classification = item.value("classification", "uncategorized");
        rule.priority = item.value("priority", 3U);
        bool known_severity = true;
        rule.severity = severity_from(item.value("severity", "MEDIUM"), known_severity);
        if (!known_severity) error(result, index, "severity", "unsupported severity");
        rule.suppression_key = item.value("suppression_key", "");
        if (item.contains("threshold")) {
            const auto& threshold = item["threshold"];
            if (!threshold.is_object() || !threshold.contains("count") || !threshold.contains("seconds") ||
                !threshold["count"].is_number_unsigned() || !threshold["count"].get<std::uint32_t>() ||
                !threshold["seconds"].is_number_unsigned() || !threshold["seconds"].get<std::uint32_t>())
                error(result, index, "threshold", "threshold requires positive count and seconds");
            else rule.threshold = Threshold{threshold["count"].get<std::uint32_t>(), threshold["seconds"].get<std::uint32_t>()};
        }
        result.rules.push_back(std::move(rule));
    }
    if (!result.valid()) result.rules.clear();
    return result;
}

const char* action_name(RuleAction action) noexcept { return action == RuleAction::alert ? "ALERT" : "LOG"; }
const char* severity_name(RuleSeverity severity) noexcept {
    switch (severity) { case RuleSeverity::info: return "INFO"; case RuleSeverity::low: return "LOW"; case RuleSeverity::medium: return "MEDIUM"; case RuleSeverity::high: return "HIGH"; case RuleSeverity::critical: return "CRITICAL"; }
    return "MEDIUM";
}

std::string rule_format_documentation() {
    return "Delta-NIDS JSON rules support passive ALERT/LOG actions, protocol, service, buffer, content, direction, ports, thresholds, and metadata. Active actions such as DROP, REJECT, BLOCK, and REPLACE are unsupported.";
}

}  // namespace delta_nids::detection
