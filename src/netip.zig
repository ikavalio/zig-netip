const std = @import("std");

// TODO:
// 1. Ip6AddrScoped
// 2. Ip4Prefix
// 3. Ip6Prefix
// 4. Data structures?

const v4addr = @import("./ip4addr.zig");
const v6addr = @import("./ip6addr.zig");

pub const Ip4AddrParseError = v4addr.ParseError;
pub const Ip6AddrParseError = v6addr.ParseError;

pub const Ip4Addr = v4addr.Addr;
pub const Ip6Addr = v6addr.Addr;
