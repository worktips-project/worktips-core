#pragma once
#include <worktipsmq/string_view.h>
#include <iterator>

namespace tools {

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(worktipsmq::string_view s1, worktipsmq::string_view s2) {
  return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
      return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

/// Returns true if the first string matches any of the given strings case-insensitively.  Arguments
/// must be string literals, std::string, or worktipsmq::string_views
#ifdef __cpp_fold_expressions
template <typename S1, typename... S>
bool string_iequal_any(const S1& s1, const S&... s) {
  return (string_iequal(s1, s) || ...);
}
#else
template <typename S1>
constexpr bool string_iequal_any(const S1& s1) {
  return false;
}
template <typename S1, typename S2, typename... S>
bool string_iequal_any(const S1& s1, const S2& s2, const S&... s) {
  return string_iequal(s1, s2) || string_iequal_any(s1, s...);
}
#endif

/// Returns a string_view that views the data of the given object; this is not something you want to
/// do unless the struct is specifically design to be used this way.  The value must be a standard
/// layout type; it should really require is_trivial, too, but we have classes (like crypto keys)
/// that aren't C++-trivial but are still designed to be accessed this way.
template <typename T>
worktipsmq::string_view view_guts(const T& val) {
    static_assert(std::is_standard_layout<T>(), "cannot safely access non-trivial class as string_view");
    return {reinterpret_cast<const char *>(&val), sizeof(val)};
}

/// Convenience wrapper around the above that also copies the result into a new string
template <typename T>
std::string copy_guts(const T& val) {
  return std::string{view_guts(val)};
}

}
