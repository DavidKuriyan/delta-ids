#include <cassert>
#include <string>

#include "detection/rule.h"

int main() {
    const auto valid = delta_nids::detection::load_rules("tests/fixtures/valid.rules.json");
    assert(valid.valid());
    assert(valid.rules.size() == 1);
    assert(valid.rules.front().sid == 1000001);
    assert(valid.rules.front().service == delta_nids::protocol::Service::http);
    assert(valid.rules.front().buffer == delta_nids::detection::BufferName::http_uri);
    assert(valid.rules.front().threshold.has_value());

    const auto invalid = delta_nids::detection::load_rules("tests/fixtures/invalid.rules.json");
    assert(!invalid.valid());
    assert(invalid.rules.empty());
    assert(invalid.errors.size() >= 3);
    return 0;
}
