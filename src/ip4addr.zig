const std = @import("std");

const math = std.math;
const mem = std.mem;
const net = std.net;
const testing = std.testing;

const addrlib = @import("./addr_value.zig");
const util = @import("./utils.zig");
const v6 = @import("./ip6addr.zig");

/// IPv4 parsing errors.
pub const ParseError = error{
    InvalidCharacter,
    LeadingZero,
    EmptyOctet,
    TooManyOctets,
    NotEnoughOctets,
    Overflow,
};

/// IPv4 address.
pub const Addr = packed struct {
    const Self = @This();
    /// The underlying ValueType of the wrapped value.
    pub const ValueType = addrlib.AddrValue(u32);

    addr: ValueType,

    /// Create an Addr directly from the value.
    pub fn init(v: u32) Self {
        return Self{ .addr = ValueType.init(v) };
    }

    /// Create an address from the array of arbitrary integer values.
    /// Elements of the array are ordered in the network order (most-significant first).
    /// Each integer value has the network byte order.
    pub fn fromArrayNetOrder(comptime E: type, a: [ValueType.size / @sizeOf(E)]E) Self {
        return Self{ .addr = ValueType.fromArrayNetOrder(E, a) };
    }

    /// Create an address from the array of arbitrary integer values.
    /// Elements of the array are ordered in the network order (most-significant first).
    /// Each integer value has the native byte order.
    pub fn fromArray(comptime E: type, a: [ValueType.size / @sizeOf(E)]E) Self {
        return Self{ .addr = ValueType.fromArray(E, a) };
    }

    /// Create an address from the std.net.Ip4Address.
    /// The conversion is lossy and the port information
    /// is discarded.
    pub fn fromNetAddress(a: net.Ip4Address) Self {
        const bs = @ptrCast(*const [4]u8, &a.sa.addr);
        return fromArrayNetOrder(u8, bs.*);
    }

    /// Parse the address from the string representation.
    /// The method supports only the standard representation of the
    /// IPv4 address.
    pub fn parse(s: []const u8) ParseError!Self {
        var octs: [4]u8 = [_]u8{0} ** 4;
        var len: u8 = 0;
        var ix: u8 = 0;

        for (s) |c, i| {
            switch (c) {
                '0'...'9' => {
                    if (octs[ix] == 0 and len > 0) {
                        return ParseError.LeadingZero;
                    }
                    octs[ix] = math.mul(u8, octs[ix], 10) catch return ParseError.Overflow;
                    octs[ix] = math.add(u8, octs[ix], c - '0') catch return ParseError.Overflow;
                    len += 1;
                },
                '.' => {
                    // dot in the wrong place
                    if (i == 0 or i == s.len - 1 or s[i - 1] == '.') {
                        return ParseError.EmptyOctet;
                    }

                    if (ix >= 3) {
                        return ParseError.TooManyOctets;
                    }

                    ix += 1;
                    len = 0;
                },
                else => return ParseError.InvalidCharacter,
            }
        }

        if (ix < 3) {
            return ParseError.NotEnoughOctets;
        }

        return fromArray(u8, octs);
    }

    /// Returns the underlying address value.
    pub fn value(self: Self) u32 {
        return self.addr.v;
    }

    /// Convert the address to an array of generic integer values.
    /// Elements of the array are ordered in the network order (most-significant first).
    /// Each integer value has the network byte order.
    pub fn toArrayNetOrder(self: Self, comptime E: type) [ValueType.size / @sizeOf(E)]E {
        return self.addr.toArrayNetOrder(E);
    }

    /// Convert the address to an array of generic integer values.
    /// Elemenets of the array is ordered in the network order (most-significant first).
    /// Each integer value has the native byte order.
    pub fn toArray(self: Self, comptime E: type) [ValueType.size / @sizeOf(E)]E {
        return self.addr.toArray(E);
    }

    /// Get an arbitrary integer value from the address.
    /// The value always has the native byte order.
    pub fn get(self: Self, comptime E: type, i: ValueType.PositionType) E {
        return self.addr.get(E, i);
    }

    /// Convert the address to the std.net.Ip4Address.
    /// Since the value doesn't carry port information,
    /// it must be provided as an argument.
    pub fn toNetAddress(self: Self, port: u16) net.Ip4Address {
        return net.Ip4Address.init(self.toArrayNetOrder(u8), port);
    }

    /// Returun an equivalent IPv4-mapped IPv6 address
    /// in the '::ffff:0:0/96'.
    pub fn toIp6(self: Self) v6.Addr {
        return v6.Addr{ .addr = v6.Addr.ValueType{ .v = 0xffff00000000 | @as(u128, self.addr.v) } };
    }

    const FormatMode = struct {
        fmt: []const u8,
    };

    fn formatMode(comptime fmt: []const u8) FormatMode {
        var mode = FormatMode{ .fmt = "" };
        var mode_set = false;

        inline for (fmt) |f| {
            if (mode_set) {
                util.invalidFmtErr(fmt, Self);
            }

            mode.fmt = switch (f) {
                'x' => "x", // hex
                'X' => "x:0>2", // padded hex
                'b' => "b", // bin
                'B' => "b:0>8", // padded bin
                else => util.invalidFmtErr(fmt, Self),
            };

            mode_set = true;
        }

        return mode;
    }

    /// Print the address. A number of non-standard (e.g. non-empty)
    /// specifiers are supported:
    ///  * x - will print all octets as hex numbers instead of base-10.
    ///  * X - will do the same as 'x', but will also ensure that each value is padded.
    ///  * b - will print all octets as binary numbers instead of base-10.
    ///  * B - will do the same as 'b', but will also ensure that each value is padded.
    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = options;

        const mode = comptime formatMode(fmt);
        const blk = "{" ++ mode.fmt ++ "}";
        const fmt_expr = blk ++ ("." ++ blk) ** 3;

        const bs = self.toArray(u8);

        try std.fmt.format(out_stream, fmt_expr, .{
            bs[0],
            bs[1],
            bs[2],
            bs[3],
        });
    }

    /// Compare two addresses.
    pub fn order(self: Self, other: Self) math.Order {
        return math.order(self.value(), other.value());
    }
};

test "Ip4 Address/sizeOf" {
    try testing.expectEqual(@sizeOf(u32), @sizeOf(Addr));
}

test "Ip4 Address/fromArrayX" {
    // 192 168 73 79 <-> c0 a8 49 3b
    const expected: u32 = 0xc0a8493b;
    const input_u8 = [_]u8{ 0xc0, 0xa8, 0x49, 0x3b };
    const input_u16_native = [_]u16{ 0xc0a8, 0x493b };
    const input_u16_net = [_]u16{
        mem.nativeToBig(u16, 0xc0a8),
        mem.nativeToBig(u16, 0x493b),
    };

    try testing.expectEqual(expected, Addr.fromArrayNetOrder(u8, input_u8).value());
    try testing.expectEqual(expected, Addr.fromArray(u8, input_u8).value());
    try testing.expectEqual(expected, Addr.fromArrayNetOrder(u16, input_u16_net).value());
    try testing.expectEqual(expected, Addr.fromArray(u16, input_u16_native).value());
}

test "Ip4 Address/toArrayX" {
    // 192 168 73 79 <-> c0 a8 49 3b
    const value: u32 = 0xc0a8493b;
    const addr = Addr.init(value);
    const out_u8 = [_]u8{ 0xc0, 0xa8, 0x49, 0x3b };
    const out_u16_native = [_]u16{ 0xc0a8, 0x493b };
    const out_u16_net = [_]u16{
        mem.nativeToBig(u16, 0xc0a8),
        mem.nativeToBig(u16, 0x493b),
    };

    try testing.expectEqual(out_u8, addr.toArray(u8));
    try testing.expectEqual(out_u8, addr.toArrayNetOrder(u8));
    try testing.expectEqual(out_u16_native, addr.toArray(u16));
    try testing.expectEqual(out_u16_net, addr.toArrayNetOrder(u16));
}

test "Ip4 Address/Parse" {
    const comp_time_one = comptime try Addr.parse("0.0.0.1");

    try testing.expectEqual(@as(u32, 1), comp_time_one.value());

    try testing.expectEqual(
        Addr.fromArray(u8, [_]u8{ 192, 168, 30, 15 }),
        (try Addr.parse("192.168.30.15")),
    );
    try testing.expectEqual(
        Addr.fromArray(u8, [_]u8{ 0, 0, 0, 0 }),
        (try Addr.parse("0.0.0.0")),
    );
    try testing.expectEqual(
        Addr.fromArray(u8, [_]u8{ 255, 255, 255, 255 }),
        (try Addr.parse("255.255.255.255")),
    );

    try testing.expectError(ParseError.NotEnoughOctets, Addr.parse(""));
    try testing.expectError(ParseError.NotEnoughOctets, Addr.parse("123"));
    try testing.expectError(ParseError.NotEnoughOctets, Addr.parse("1.1.1"));
    try testing.expectError(ParseError.InvalidCharacter, Addr.parse("20::1:1"));
    try testing.expectError(ParseError.Overflow, Addr.parse("256.1.1.1"));
    try testing.expectError(ParseError.LeadingZero, Addr.parse("254.01.1.1"));
    try testing.expectError(ParseError.EmptyOctet, Addr.parse(".1.1.1"));
    try testing.expectError(ParseError.EmptyOctet, Addr.parse("1.1..1"));
    try testing.expectError(ParseError.EmptyOctet, Addr.parse("1.1.1."));
    try testing.expectError(ParseError.TooManyOctets, Addr.parse("1.1.1.1.1"));
}

test "Ip4 Address/get" {
    const addr = Addr.fromArray(u8, [_]u8{ 192, 168, 30, 15 });

    try testing.expectEqual(@as(u8, 168), addr.get(u8, 1));
    try testing.expectEqual(@as(u16, 0x1e0f), addr.get(u16, 1));
}

test "Ip4 Address/convert to and from std.net.Ip4Address" {
    // 192 168 73 79 <-> c0 a8 49 4f
    const value: u32 = 0xc0a8494f;
    const sys_addr = try net.Ip4Address.parse("192.168.73.79", 0);

    const addr = Addr.fromNetAddress(sys_addr);
    try testing.expectEqual(value, addr.value());
    try testing.expectEqual(sys_addr.sa.addr, addr.toNetAddress(5).sa.addr);
}

test "Ip4 Address/convert to Ip6 Address" {
    const value: u32 = 0xc0a8494f;
    const eq_value: u128 = 0x00ffffc0a8494f;
    try testing.expectEqual(eq_value, Addr.fromArray(u32, [_]u32{value}).toIp6().value());
}

test "Ip4 Address/format" {
    try testing.expectFmt("192.168.73.72", "{}", .{try Addr.parse("192.168.73.72")});
    try testing.expectFmt("c0.a8.49.1", "{x}", .{try Addr.parse("192.168.73.1")});
    try testing.expectFmt("c0.a8.01.01", "{X}", .{try Addr.parse("192.168.1.1")});
    try testing.expectFmt("11000000.10101000.1001001.1001000", "{b}", .{try Addr.parse("192.168.73.72")});
    try testing.expectFmt("11000000.10101000.01001001.01001000", "{B}", .{try Addr.parse("192.168.73.72")});
}

test "Ip4 Address/comparison" {
    const addr1 = Addr.init(1);
    const addr2 = Addr.init(2);

    try testing.expectEqual(math.Order.eq, addr1.order(addr1));
    try testing.expectEqual(math.Order.eq, addr2.order(addr2));
    try testing.expectEqual(math.Order.lt, addr1.order(addr2));
    try testing.expectEqual(math.Order.gt, addr2.order(addr1));
}
