// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#ifdef NIGHTLY_BUILD
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#endif

#include <ctime>
#include <iomanip>
#include <sstream>
#include <string_view>

#include <fmt/format.h>
#include "common/net/net.h"
#include "common/scm_rev.h"
#include "update_checker.h"

#include "common/logging.h"

namespace {

// Parses the UTC ISO-8601 build timestamp (e.g. 2026-10-22T03:04:05Z) into Unix seconds.
std::optional<u64> ParseTimestamp(std::string_view value) {
    std::tm tm{};
    std::istringstream stream{std::string{value}};
    stream >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (stream.fail()) {
        return std::nullopt;
    }
#ifdef _WIN32
    const auto seconds = _mkgmtime(&tm);
#else
    const auto seconds = timegm(&tm);
#endif
    if (seconds < 0) {
        return std::nullopt;
    }
    return static_cast<u64>(seconds);
}

} // namespace

std::optional<Common::Net::Release> UpdateChecker::GetUpdate() {
    const auto latest = Common::Net::GetLatestRelease();
    if (!latest) return std::nullopt;

    LOG_INFO(Frontend, "Received update {}", latest->title);

#ifdef NIGHTLY_BUILD
    std::vector<std::string> result;

    boost::split(result, latest->tag, boost::is_any_of("."));
    if (result.size() != 2)
        return std::nullopt;

    const std::string tag = result[1];

    boost::split(result, std::string{Common::g_build_version}, boost::is_any_of("-"));
    if (result.empty())
        return std::nullopt;

    const std::string build = result[0];
#else
    const std::string tag = latest->tag;
    const std::string build = Common::g_build_version;
#endif

    if (tag == build)
        return std::nullopt;

#ifndef NIGHTLY_BUILD
    // Builds from a branch report their commit rather than a tag, so a differing tag alone does
    // not mean the release is newer. Only offer releases published after this build was made.
    if (const auto built_at = ParseTimestamp(Common::g_build_date);
        built_at && latest->published != 0 && latest->published <= *built_at) {
        LOG_INFO(Frontend, "Release {} is not newer than this build ({})", tag, build);
        return std::nullopt;
    }
#endif

    return latest;
}
