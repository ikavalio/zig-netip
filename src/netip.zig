const std = @import("std");
const testing = std.testing;
const math = std.math;

// TODO:
// - Ip6AddrScoped
// - Aggregate Addr type
// - Prefix Set/Map
// - Well known addresses and prefixes
// - Data structures

pub fn order(a: anytype, b: anytype) math.Order {
    return a.order(b);
}

const addr = @import("./addr.zig");
const prefix = @import("./prefix.zig");

pub const Ip4Addr = addr.Ip4Addr;
pub const Ip6Addr = addr.Ip6Addr;

pub const PrefixInclusion = prefix.Inclusion;

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
    try testing.expect(Ip4Addr.parse("-=_=-") == Ip4Addr.ParseError.InvalidCharacter);

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
    try testing.expect(Ip6Addr.parse("-=_=-") == Ip6Addr.ParseError.InvalidCharacter);

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
    const prefix1 = try Ip6Prefix.init(try Ip6Addr.parse("2001:db8:85a3::1"), 48);
    const prefix2 = try Ip6Prefix.parse("2001:db8:85a3::/48");

    // compare mask bits
    try testing.expectEqual(prefix1.maskBits(), prefix2.maskBits());

    // handle parsing errors
    try testing.expectError(Ip6Prefix.ParseError.Overflow, Ip6Prefix.parse("2001:db8::/256"));

    // print
    try testing.expectFmt("2001:db8:85a3::1/48", "{}", .{prefix1});
    try testing.expectFmt("2001:0db8:85a3::0001/48", "{X}", .{prefix1});
    try testing.expectFmt("2001:db8:85a3::-2001:db8:85a3:ffff:ffff:ffff:ffff:ffff", "{R}", .{prefix1});

    // contains address
    try testing.expect(prefix1.containsAddr(try Ip6Addr.parse("2001:db8:85a3:cafe::efac")));

    // inclusion and overlap test
    try testing.expectEqual(PrefixInclusion.sub, prefix1.testInclusion(try Ip6Prefix.parse("2001:db8::/32")));
    try testing.expect(prefix2.overlaps(try Ip6Prefix.parse("2001:db8::/32")));
}

test "Ip4Prefix Example" {
    // create a prefix
    const prefix1 = try Ip4Prefix.init(try Ip4Addr.parse("192.0.2.1"), 24);
    const prefix2 = try Ip4Prefix.parse("192.0.2.1/24");

    // compare mask bits
    try testing.expectEqual(prefix1.maskBits(), prefix2.maskBits());

    // handle parsing errors
    try testing.expectError(Ip4Prefix.ParseError.Overflow, Ip4Prefix.parse("192.0.2.1/42"));

    // print
    try testing.expectFmt("192.0.2.0/24", "{}", .{prefix1.canonical()});
    try testing.expectFmt("192.0.2.0-192.0.2.255", "{R}", .{prefix1});

    // contains address
    try testing.expect(prefix1.containsAddr(try Ip4Addr.parse("192.0.2.42")));

    // inclusion and overlap test
    try testing.expectEqual(PrefixInclusion.sub, prefix1.testInclusion(try Ip4Prefix.parse("192.0.2.0/16")));
    try testing.expect(prefix2.overlaps(try Ip4Prefix.parse("192.0.2.0/16")));
}
