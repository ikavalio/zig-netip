const std = @import("std");

const builtin = std.builtin;
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const net = std.net;
const testing = std.testing;

const addrlib = @import("./addr_value.zig");
const util = @import("./utils.zig");
const v6 = @import("./ip6addr.zig");

pub const ParseError = error{
    InvalidCharacter,
    LeadingZero,
    EmptyOctet,
    TooManyOctets,
    NotEnoughOctets,
    Overflow,
};

pub const Addr = packed struct {
    const Self = @This();
    pub const ValueType = addrlib.AddrValue(u32);

    addr: ValueType,

    pub fn fromArrayNetOrder(comptime E: type, a: [ValueType.size / @sizeOf(E)]E) Self {
        return Self{ .addr = ValueType.fromArrayNetOrder(E, a) };
    }

    pub fn fromArray(comptime E: type, a: [ValueType.size / @sizeOf(E)]E) Self {
        return Self{ .addr = ValueType.fromArray(E, a) };
    }

    pub fn fromNetAddress(a: net.Ip4Address) Self {
        const bs = @ptrCast(*const [4]u8, &a.sa.addr);
        return fromArrayNetOrder(u8, bs.*);
    }

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

    pub fn value(self: Self) u32 {
        return self.addr.v;
    }

    pub fn toArrayNetOrder(self: Self, comptime E: type) [ValueType.size / @sizeOf(E)]E {
        return self.addr.toArrayNetOrder(E);
    }

    pub fn toArray(self: Self, comptime E: type) [ValueType.size / @sizeOf(E)]E {
        return self.addr.toArray(E);
    }

    pub fn get(self: Self, comptime E: type, i: ValueType.PositionType) E {
        return self.addr.get(E, i);
    }

    pub fn toNetAddress(self: Self) net.Ip4Address {
        return net.Ip4Address.init(self.toArrayNetOrder(u8), 0);
    }

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
    const addr = Addr.fromArray(u32, [_]u32{value});
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
    try testing.expectEqual(sys_addr.sa.addr, addr.toNetAddress().sa.addr);
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
