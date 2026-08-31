#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "behavioral/behavioral_detector.h"
#include "detection/detection_engine.h"

namespace delta_nids::alert {

enum class Severity { info, low, medium, high, critical };

struct Alert {
    std::uint64_t id = 0;
    std::int64_t first_seen = 0;
    std::int64_t last_seen = 0;
    std::uint64_t occurrence_count = 0;
    std::uint64_t suppressed_count = 0;
    Severity severity = Severity::medium;
    int confidence = 0;
    int risk = 0;
    detection::DetectionType detection_type = detection::DetectionType::signature;
    std::uint32_t gid = 1;
    std::uint32_t sid = 0;
    std::uint32_t revision = 0;
    std::string source_ip;
    std::uint16_t source_port = 0;
    std::string destination_ip;
    std::uint16_t destination_port = 0;
    std::string protocol;
    std::string service;
    std::uint64_t flow_id = 0;
    std::uint64_t traffic_id = 0;
    std::string message;
    std::string evidence;
    std::string explanation;
    std::string fingerprint;
};

struct AlertConfig {
    std::int64_t deduplication_window_seconds = 60;
    std::int64_t suppression_window_seconds = 60;
    std::size_t maximum_alerts = 100000;
    std::size_t maximum_events_per_window = 1000;
};

[[nodiscard]] const char* severity_name(Severity severity) noexcept;
[[nodiscard]] Severity severity_from_rule(detection::RuleSeverity severity) noexcept;
[[nodiscard]] std::string fingerprint_for(const detection::DetectionEvent& event,
                                          const std::string& source_ip,
                                          const std::string& destination_ip);

}  // namespace delta_nids::alert
