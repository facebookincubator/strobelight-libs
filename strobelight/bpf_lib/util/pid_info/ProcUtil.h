// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <filesystem>
#include <istream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace facebook::pid_info {

struct BuildInfo;
struct BinaryInfo;
enum class ArchiveType;

bool nextToken(
    const std::string_view& sv,
    const std::string_view& delim,
    size_t startPos,
    std::string_view& result);

bool tokenize(
    const std::string_view& source,
    const std::string_view& delimiter,
    std::vector<std::string_view>& destination);

bool getCgroupNames(
    const std::string_view& cg_line,
    std::vector<std::string_view>& subsystems,
    std::vector<std::string_view>& cg_names);

bool populateCgMap(
    std::map<std::string, std::string>& cg_map,
    std::vector<std::string_view>& subsystems,
    std::vector<std::string_view>& cg_names);

/*
 * forceJoinNormalise joins \p lhs and \p rhs but also:
 * - [force]
 * \p lhs is treated as is or '/', if it is empty
 * \p rhs is always treated as a relative path, even if starts with '/'
 * - [normalize] The resulting path has normal form as per
 * std::filesystem::path::lexically_normal.
 */
std::filesystem::path forceJoinNormalise(
    const std::filesystem::path& lhs,
    const std::filesystem::path& rhs);

std::filesystem::path buildProcRelativePath(
    const std::filesystem::path& path,
    const std::filesystem::path& procRoot,
    const std::filesystem::path& procCwd);

bool haveEffectiveSysAdminCapability();

} // namespace facebook::pid_info
