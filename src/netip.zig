const std = @import("std");
const testing = std.testing;
const math = std.math;

// TODO:
// 1. Ip6AddrScoped
// 2. Ip4Prefix
// 3. Ip6Prefix
// 4. Data structures?

pub fn order(a: anytype, b: anytype) math.Order {
    return a.order(b);
}

const v4addr = @import("./ip4addr.zig");
const v6addr = @import("./ip6addr.zig");
const prefix = @import("./prefix.zig");

pub const Ip4AddrParseError = v4addr.ParseError;
pub const Ip6AddrParseError = v6addr.ParseError;

pub const Ip4Addr = v4addr.Addr;
pub const Ip6Addr = v6addr.Addr;

pub const PrefixParseError = prefix.ParseError;

pub const Ip4Prefix = prefix.Ip4Prefix;
pub const Ip6Prefix = prefix.Ip6Prefix;

test "Ip4Addr Example" {
    // create
    const addr1 = comptime try Ip4Addr.parse("192.0.2.1");
    const addr2 = try Ip4Addr.parse("192.0.2.1");
    const addr3 = Ip4Addr.fromArray(u8, [_]u8{ 192, 0, 2, 2 });
    const addr4 = Ip4Addr.fromArray(u16, [_]u16{ 0xC000, 0x0202 });
    const addr5 = Ip4Addr.init(0xC0000203);
    const addr6 = Ip4Addr.fromNetAddress(try std.net.Ip4Address.parse("192.0.2.3", 1));

    // handle parsing errors
    try testing.expect(Ip4Addr.parse("-=_=-") == Ip4AddrParseError.InvalidCharacter);

    // copy
    const addr7 = addr5;
    const addr8 = addr3;

    // compare via values
    try testing.expectEqual(math.Order.eq, order(addr1, addr2));
    try testing.expectEqual(math.Order.lt, order(addr1, addr8));
    try testing.expectEqual(math.Order.gt, order(addr7, addr1));
    try testing.expect(addr3.value() == addr4.value());
    try testing.expect(addr4.value() != addr6.value());
    try testing.expect(addr5.value() > addr4.value());

    // print
    try testing.expectFmt("192.0.2.1", "{}", .{addr1});
    try testing.expectFmt("c0.00.02.02", "{X}", .{addr3});
    try testing.expectFmt("11000000.0.10.11", "{b}", .{addr5});
}

test "Ip6Addr Example" {
    // create
    const addr1 = comptime try Ip6Addr.parse("2001:db8::1");
    const addr2 = try Ip6Addr.parse("2001:db8::1");
    const addr3 = Ip6Addr.fromArray(u8, [_]u8{ 0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 });
    const addr4 = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2 });
    const addr5 = Ip6Addr.init(0x2001_0db8_0000_0000_0000_0000_0000_0003);
    const addr6 = Ip6Addr.fromNetAddress(try std.net.Ip6Address.parse("2001:db8::3", 1));

    // handle parsing errors
    try testing.expect(Ip6Addr.parse("-=_=-") == Ip6AddrParseError.InvalidCharacter);

    // copy
    const addr7 = addr5;
    const addr8 = addr3;

    // compare via values
    try testing.expectEqual(math.Order.eq, order(addr1, addr2));
    try testing.expectEqual(math.Order.lt, order(addr1, addr8));
    try testing.expectEqual(math.Order.gt, order(addr7, addr1));
    try testing.expect(addr3.value() == addr4.value());
    try testing.expect(addr4.value() != addr6.value());
    try testing.expect(addr5.value() > addr4.value());

    // print
    try testing.expectFmt("2001:db8::1", "{}", .{addr1});
    try testing.expectFmt("2001:db8:0:0:0:0:0:2", "{xE}", .{addr3});
    try testing.expectFmt("2001:0db8::0003", "{X}", .{addr5});
    try testing.expectFmt("2001:0db8:0000:0000:0000:0000:0000:0001", "{XE}", .{addr2});
}

test "Ip6Prefix Example" {
    // create a prefix
    const prefix1 = Ip6Prefix.init(try Ip6Addr.parse("2001:db8::1"), 96);
    const prefix2 = try Ip6Prefix.parse("2001:db8::/96");

    // compare mask bits
    try testing.expectEqual(prefix1.maskBits(), prefix2.maskBits());

    // handle parsing errors
    try testing.expectError(PrefixParseError.Overflow, Ip6Prefix.parse("2001:db8::/256"));
}

test "Ip4Prefix Example" {
    // create a prefix
    const prefix1 = Ip4Prefix.init(try Ip4Addr.parse("192.0.2.1"), 24);
    const prefix2 = try Ip4Prefix.parse("192.0.2.1/24");

    // compare mask bits
    try testing.expectEqual(prefix1.maskBits(), prefix2.maskBits());

    // handle parsing errors
    try testing.expectError(PrefixParseError.Overflow, Ip4Prefix.parse("192.0.2.1/42"));
}
