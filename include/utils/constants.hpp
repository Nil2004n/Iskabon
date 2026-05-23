#pragma once
#include <string_view>

namespace iskabon {

constexpr std::string_view APP_NAME    = "Iskabon";
constexpr std::string_view APP_AUTHOR  = "Nil";
constexpr std::string_view APP_VERSION = "0.1.0";

// ASCII Ace-of-Spades banner – verified at runtime via SHA-256.
// Any fork that changes this string will fail the integrity gate.
constexpr std::string_view LOGO = R"(
┌──────────────────────────────────────────────────────────┐
│                        A♠                               │
│                     .-"""-.                            │
│                    / .===. \                           │
│                    \/ 6 6 \/                           │
│                    ( \___/ )                           │
│___ooo__________ooo__\_____/____________________________│
│                                                         │
│                 Iskabon by Nil                          │
└──────────────────────────────────────────────────────────┘
)";

// SHA-256 of LOGO above.  CI must regenerate this when logo changes upstream.
constexpr std::string_view LOGO_SHA256 =
    "f5f6a94fce7e8c9f0678ad45db9be841f8053183b76d62fc568e4c5214af9c63";

}  // namespace iskabon
