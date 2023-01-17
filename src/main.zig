const std = @import("std");
const builtin = std.builtin;
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const net = std.net;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Endian = std.builtin.Endian;

// TODO:
// 1. Ip6AddrScoped
// 2. Ip4Prefix
// 3. Ip6Prefix
// 4. Data structures?

fn invalidFmtErr(comptime fmt: []const u8, value: type) void {
    @compileError("invalid format string '" ++ fmt ++ "' for type '" ++ @typeName(value) ++ "'");
}

fn AddrValue(comptime T: type) type {
    if (T != u128 and T != u32) {
        @compileError("unknown address type '" ++ @typeName(T) ++ "' (only u128 and u32 are supported)");
    }

    const type_size = @sizeOf(T);
    assert(type_size > 0 and (type_size & (type_size - 1) == 0));

    return packed struct {
        const Self = @This();
        const PositionType = math.Log2Int(T);
        const size = type_size;

        v: T,

        // create an address from the slice of integer values.
        // elements of the array are ordered in the network order.
        // each integer value has the network byte order.
        inline fn fromArrayNetOrder(comptime E: type, a: [size / @sizeOf(E)]E) Self {
            const p = @ptrCast(*align(@alignOf(u8)) const [size / @sizeOf(u8)]u8, &a);
            const v = mem.bigToNative(T, std.mem.bytesToValue(T, p));
            return Self{ .v = v };
        }

        // create an address from the slice of integer values.
        // elements of the array are ordered in the network order.
        // each integer value has the native byte order.
        inline fn fromArray(comptime E: type, a: [size / @sizeOf(E)]E) Self {
            var v: T = 0;

            inline for (a) |b, i| {
                v |= @as(T, b) << (@bitSizeOf(E) * ((size / @sizeOf(E)) - 1 - i));
            }

            return Self{ .v = v };
        }

        // convert the address to an array of integer values.
        // elements of the array are ordered in the network order.
        // each integer value has the native byte order.
        pub fn toArrayNetOrder(self: Self, comptime E: type) [size / @sizeOf(E)]E {
            var a = self.toArray(E);

            inline for (a) |b, i| {
                a[i] = mem.nativeToBig(E, b);
            }

            return a;
        }

        // convert the address to an array of integer values
        // array is ordered in the network order
        // components have native order
        inline fn toArray(self: Self, comptime E: type) [size / @sizeOf(E)]E {
            var a: [size / @sizeOf(E)]E = undefined;

            inline for (a) |_, i| {
                a[i] = self.get(E, i);
            }

            return a;
        }

        // convert the address to an array of integer values
        // array is ordered in the network order
        // components have native order
        inline fn get(self: Self, comptime E: type, i: PositionType) E {
            return @truncate(E, self.v >> (@bitSizeOf(E) * (size / @sizeOf(E) - 1 - i)));
        }
    };
}

pub const Ip4AddrParseError = error{
    InvalidCharacter,
    LeadingZero,
    EmptyOctet,
    TooManyOctets,
    NotEnoughOctets,
    Overflow,
};

pub const Ip4Addr = packed struct {
    const Self = @This();
    const ValueType = AddrValue(u32);

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

    pub fn parse(s: []const u8) Ip4AddrParseError!Self {
        var octs: [4]u8 = [_]u8{0} ** 4;
        var len: u8 = 0;
        var ix: u8 = 0;

        for (s) |c, i| {
            switch (c) {
                '0'...'9' => {
                    if (octs[ix] == 0 and len > 0) {
                        return Ip4AddrParseError.LeadingZero;
                    }
                    octs[ix] = math.mul(u8, octs[ix], 10) catch return Ip4AddrParseError.Overflow;
                    octs[ix] = math.add(u8, octs[ix], c - '0') catch return Ip4AddrParseError.Overflow;
                    len += 1;
                },
                '.' => {
                    // dot in the wrong place
                    if (i == 0 or i == s.len - 1 or s[i - 1] == '.') {
                        return Ip4AddrParseError.EmptyOctet;
                    }

                    if (ix >= 3) {
                        return Ip4AddrParseError.TooManyOctets;
                    }

                    ix += 1;
                    len = 0;
                },
                else => return Ip4AddrParseError.InvalidCharacter,
            }
        }

        if (ix < 3) {
            return Ip4AddrParseError.NotEnoughOctets;
        }

        return fromArray(u8, octs);
    }

    pub fn value(self: Ip4Addr) u32 {
        return self.addr.v;
    }

    pub fn toArrayNetOrder(self: Ip4Addr, comptime E: type) [ValueType.size / @sizeOf(E)]E {
        return self.addr.toArrayNetOrder(E);
    }

    pub fn toArray(self: Ip4Addr, comptime E: type) [ValueType.size / @sizeOf(E)]E {
        return self.addr.toArray(E);
    }

    pub fn get(self: Ip4Addr, comptime E: type, i: ValueType.PositionType) E {
        return self.addr.get(E, i);
    }

    pub fn toNetAddress(self: Ip4Addr) net.Ip4Address {
        return net.Ip4Address.init(self.toArrayNetOrder(u8), 0);
    }

    pub fn toIp6(self: Self) Ip6Addr {
        return Ip6Addr{ .addr = Ip6Addr.ValueType{ .v = 0xffff00000000 | @as(u128, self.addr.v) } };
    }

    const FormatMode = struct {
        fmt: []const u8,
    };

    fn formatMode(comptime fmt: []const u8) FormatMode {
        var mode = FormatMode{ .fmt = "" };
        var mode_set = false;

        inline for (fmt) |f| {
            if (mode_set) {
                invalidFmtErr(fmt, Self);
            }

            mode.fmt = switch (f) {
                'x' => "x", // hex
                'X' => "x:0>2", // padded hex
                'b' => "b", // bin
                'B' => "b:0>8", // padded bin
                else => invalidFmtErr(fmt, Self),
            };

            mode_set = true;
        }

        return mode;
    }

    pub fn format(
        self: Ip4Addr,
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

pub const Ip6AddrParseError = error{
    InvalidCharacter,
    EmbeddedIp4InvalidLocation,
    EmbeddedIp4InvalidFormat,
    EmptySegment,
    MultipleEllipses,
    TooManySegments,
    NotEnoughSegments,
    AmbiguousEllipsis,
    Overflow,
};

pub const Ip6Addr = packed struct {
    const Self = @This();
    const ValueType = AddrValue(u128);

    addr: ValueType,

    pub fn fromArrayNetOrder(comptime E: type, a: [ValueType.size / @sizeOf(E)]E) Self {
        return Self{ .addr = ValueType.fromArrayNetOrder(E, a) };
    }

    pub fn fromArray(comptime E: type, a: [ValueType.size / @sizeOf(E)]E) Self {
        return Self{ .addr = ValueType.fromArray(E, a) };
    }

    pub fn fromNetAddress(a: net.Ip6Address) Self {
        const bs = @ptrCast(*const [16]u8, &a.sa.addr);
        return fromArray(u8, bs.*);
    }

    pub fn parse(input: []const u8) Ip6AddrParseError!Self {
        // parsing strategy is almost identical to https://pkg.go.dev/net/netip

        var s: []const u8 = input[0..];
        var addr: [8]u16 = [_]u16{0} ** 8;
        var ellipsis: ?usize = null;

        if (s.len >= 2 and s[0] == ':' and s[1] == ':') {
            ellipsis = 0;
            s = s[2..];
            if (s.len == 0) {
                return Ip6Addr{ .addr = ValueType{ .v = 0 } };
            }
        }

        var filled: usize = 0;

        for (addr) |_, addr_i| {
            var chunk_end: usize = 0;
            var acc: u16 = 0;

            // parse the next segment
            while (chunk_end < s.len) : (chunk_end += 1) {
                const c = s[chunk_end];
                switch (c) {
                    '0'...'9', 'a'...'f', 'A'...'F' => {
                        const d = switch (c) {
                            '0'...'9' => c - '0',
                            'a'...'f' => c - 'a' + 10,
                            'A'...'F' => c - 'A' + 10,
                            else => unreachable,
                        };

                        acc = math.shlExact(u16, acc, 4) catch return Ip6AddrParseError.Overflow;
                        acc += d;
                    },
                    '.', ':' => break,
                    else => return Ip6AddrParseError.InvalidCharacter,
                }
            }

            if (chunk_end == 0) {
                return Ip6AddrParseError.EmptySegment;
            }

            // check if this is an embedded v4 address
            if (chunk_end < s.len and s[chunk_end] == '.') {
                if ((ellipsis == null and addr_i != 6) or addr_i > 6) {
                    // wrong position to insert 4 bytes of the embedded ip4
                    return Ip6AddrParseError.EmbeddedIp4InvalidLocation;
                }

                // discard the acc and parse the whole fragment as v4
                const ip4 = Ip4Addr.parse(s[0..]) catch return Ip6AddrParseError.EmbeddedIp4InvalidFormat;
                const segs = ip4.toArray(u16);
                inline for (segs) |d, j| {
                    addr[addr_i + j] = d;
                }
                filled += segs.len;
                s = s[s.len..];
                break;
            }

            // save the segment
            addr[addr_i] = acc;
            filled += 1;
            s = s[chunk_end..];
            if (s.len == 0) {
                break;
            }

            // the following char must be ':'
            std.debug.assert(s[0] == ':');
            if (s.len == 1) {
                return Ip6AddrParseError.EmptySegment;
            }
            s = s[1..];

            // check one more char in case it's ellipsis '::'
            if (s[0] == ':') {
                if (ellipsis) |_| {
                    return Ip6AddrParseError.MultipleEllipses;
                }

                ellipsis = filled;
                s = s[1..];
                if (s.len == 0) {
                    break;
                }
            }
        }

        if (s.len != 0) {
            return Ip6AddrParseError.TooManySegments;
        }

        if (filled < addr.len) {
            if (ellipsis) |e| {
                const zs = addr.len - filled;
                mem.copyBackwards(u16, addr[e + zs .. addr.len], addr[e..filled]);
                mem.set(u16, addr[e .. e + zs], 0);
            } else {
                return Ip6AddrParseError.NotEnoughSegments;
            }
        } else if (ellipsis) |_| {
            return Ip6AddrParseError.AmbiguousEllipsis;
        }

        return fromArray(u16, addr);
    }

    pub fn value(self: Ip6Addr) u128 {
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

    pub fn toNetAddress(self: Self) net.Ip6Address {
        return net.Ip6Address.init(self.toArray(u8), 0, 0, 0);
    }

    pub fn toIp4(self: Self) ?Ip4Addr {
        if (self.addr.v >> 32 != 0xffff) {
            return null;
        }

        return Ip4Addr.fromArray(u32, [_]u32{@truncate(u32, self.addr.v)});
    }

    const FormatMode = struct {
        fmt: []const u8,
        expand: bool,
    };

    fn formatMode(comptime fmt: []const u8) FormatMode {
        var mode = FormatMode{ .fmt = "x", .expand = false };
        var mode_set = false;

        inline for (fmt) |f| {
            switch (f) {
                'E' => {
                    if (mode.expand) {
                        invalidFmtErr(fmt, Self);
                    }

                    mode.expand = true;
                },
                'x', 'X', 'b', 'B' => {
                    if (mode_set) {
                        invalidFmtErr(fmt, Self);
                    }

                    mode.fmt = switch (f) {
                        'x' => "x", // hex
                        'X' => "x:0>4", // padded hex
                        'b' => "b", // bin
                        'B' => "b:0>16", // padded bin
                        else => unreachable,
                    };

                    mode_set = true;
                },
                else => invalidFmtErr(fmt, Self),
            }
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
        const fmt_seg = "{" ++ mode.fmt ++ "}";

        const segs = self.toArray(u16);

        var zero_start: u8 = 255;
        var zero_end: u8 = 255;
        var rlen: u8 = 0;

        for (segs) |c, i| {
            switch (c) {
                0 => rlen += 1,
                else => {
                    if (rlen > 0 and rlen > zero_end - zero_start) {
                        zero_end = @truncate(u8, i);
                        zero_start = zero_end - rlen;
                    }
                    rlen = 0;
                },
            }
        }

        var i: u8 = 0;
        while (i < segs.len) : (i += 1) {
            if (!mode.expand and i == zero_start) {
                try out_stream.writeAll("::");
                i = zero_end;
            } else if (i > 0) {
                try out_stream.writeAll(":");
            }

            try std.fmt.format(out_stream, fmt_seg, .{segs[i]});
        }
    }
};

test "Ip4 Address/sizeOf" {
    try testing.expectEqual(@sizeOf(u32), @sizeOf(Ip4Addr));
}

test "Ip6 Address/sizeOf" {
    try testing.expectEqual(@sizeOf(u128), @sizeOf(Ip6Addr));
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

    try testing.expectEqual(expected, Ip4Addr.fromArrayNetOrder(u8, input_u8).value());
    try testing.expectEqual(expected, Ip4Addr.fromArray(u8, input_u8).value());
    try testing.expectEqual(expected, Ip4Addr.fromArrayNetOrder(u16, input_u16_net).value());
    try testing.expectEqual(expected, Ip4Addr.fromArray(u16, input_u16_native).value());
}

test "Ip6 Address/fromArrayX" {
    // 2001:db8::89ab:cdef
    const expected: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const input_u8 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xab, 0xcd, 0xef };
    const input_u16_native = [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef };
    const input_u16_net = [_]u16{
        mem.nativeToBig(u16, 0x2001),
        mem.nativeToBig(u16, 0x0db8),
        0,
        0,
        0,
        0,
        mem.nativeToBig(u16, 0x89ab),
        mem.nativeToBig(u16, 0xcdef),
    };

    try testing.expectEqual(expected, Ip6Addr.fromArrayNetOrder(u8, input_u8).value());
    try testing.expectEqual(expected, Ip6Addr.fromArray(u8, input_u8).value());
    try testing.expectEqual(expected, Ip6Addr.fromArrayNetOrder(u16, input_u16_net).value());
    try testing.expectEqual(expected, Ip6Addr.fromArray(u16, input_u16_native).value());
}

test "Ip4 Address/toArrayX" {
    // 192 168 73 79 <-> c0 a8 49 3b
    const value: u32 = 0xc0a8493b;
    const addr = Ip4Addr.fromArray(u32, [_]u32{value});
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

test "Ip6 Address/toArrayX" {
    // 2001:db8::89ab:cdef
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const addr = Ip6Addr.fromArray(u128, [_]u128{value});
    const out_u8 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xab, 0xcd, 0xef };
    const out_u16_native = [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef };
    const out_u16_net = [_]u16{
        mem.nativeToBig(u16, 0x2001),
        mem.nativeToBig(u16, 0x0db8),
        0,
        0,
        0,
        0,
        mem.nativeToBig(u16, 0x89ab),
        mem.nativeToBig(u16, 0xcdef),
    };

    try testing.expectEqual(out_u8, addr.toArray(u8));
    try testing.expectEqual(out_u8, addr.toArrayNetOrder(u8));
    try testing.expectEqual(out_u16_native, addr.toArray(u16));
    try testing.expectEqual(out_u16_net, addr.toArrayNetOrder(u16));
}

test "Ip4 Address/Parse" {
    const comp_time_one = comptime try Ip4Addr.parse("0.0.0.1");

    try testing.expectEqual(@as(u32, 1), comp_time_one.value());

    try testing.expectEqual(
        Ip4Addr.fromArray(u8, [_]u8{ 192, 168, 30, 15 }),
        (try Ip4Addr.parse("192.168.30.15")),
    );
    try testing.expectEqual(
        Ip4Addr.fromArray(u8, [_]u8{ 0, 0, 0, 0 }),
        (try Ip4Addr.parse("0.0.0.0")),
    );
    try testing.expectEqual(
        Ip4Addr.fromArray(u8, [_]u8{ 255, 255, 255, 255 }),
        (try Ip4Addr.parse("255.255.255.255")),
    );

    try testing.expectError(Ip4AddrParseError.NotEnoughOctets, Ip4Addr.parse(""));
    try testing.expectError(Ip4AddrParseError.NotEnoughOctets, Ip4Addr.parse("123"));
    try testing.expectError(Ip4AddrParseError.NotEnoughOctets, Ip4Addr.parse("1.1.1"));
    try testing.expectError(Ip4AddrParseError.InvalidCharacter, Ip4Addr.parse("20::1:1"));
    try testing.expectError(Ip4AddrParseError.Overflow, Ip4Addr.parse("256.1.1.1"));
    try testing.expectError(Ip4AddrParseError.LeadingZero, Ip4Addr.parse("254.01.1.1"));
    try testing.expectError(Ip4AddrParseError.EmptyOctet, Ip4Addr.parse(".1.1.1"));
    try testing.expectError(Ip4AddrParseError.EmptyOctet, Ip4Addr.parse("1.1..1"));
    try testing.expectError(Ip4AddrParseError.EmptyOctet, Ip4Addr.parse("1.1.1."));
    try testing.expectError(Ip4AddrParseError.TooManyOctets, Ip4Addr.parse("1.1.1.1.1"));
}

test "Ip6 Address/Parse" {
    const comp_time_one = comptime try Ip6Addr.parse("::1");

    // compile time test
    try testing.expectEqual(@as(u128, 1), comp_time_one.value());

    // format tests
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("::")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("0:0::0:0")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("::0:0:0")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("0:0:0::")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("0:0:0:0::0:0:0")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("0:0:0:0:0:0:0:0")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("0:0:0:0:0:0:0.0.0.0")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("::0.0.0.0")));
    try testing.expectEqual(Ip6Addr.fromArray(u128, [_]u128{0}), (try Ip6Addr.parse("0:0::0.0.0.0")));

    // value tests
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }),
        (try Ip6Addr.parse("1:2:3:4:5:6:7:8")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x0, 0x6, 0x7, 0x8 }),
        (try Ip6Addr.parse("1:2:3:4::6:7:8")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x0, 0x0, 0x6, 0x7, 0x8 }),
        (try Ip6Addr.parse("1:2:3::6:7:8")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x7, 0x8 }),
        (try Ip6Addr.parse("::6:7:8")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 }),
        (try Ip6Addr.parse("1:2:3::")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8 }),
        (try Ip6Addr.parse("::8")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }),
        (try Ip6Addr.parse("1::")),
    );

    // embedded ipv4
    try testing.expectEqual(
        Ip6Addr.fromArray(u8, [_]u8{ 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa, 0xb, 0xc, 0xd }),
        (try Ip6Addr.parse("100::10.11.12.13")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u8, [_]u8{ 0, 0x1, 0, 0x2, 0, 0x3, 0, 0x4, 0, 0x5, 0, 0x6, 0xa, 0xb, 0xc, 0xd }),
        (try Ip6Addr.parse("1:2:3:4:5:6:10.11.12.13")),
    );

    // larger numbers
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef }),
        (try Ip6Addr.parse("2001:db8::89ab:cdef")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff }),
        (try Ip6Addr.parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
    );

    // empty or ambiguous segments
    try testing.expectError(Ip6AddrParseError.EmptySegment, Ip6Addr.parse(":::"));
    try testing.expectError(Ip6AddrParseError.EmptySegment, Ip6Addr.parse(":"));
    try testing.expectError(Ip6AddrParseError.EmptySegment, Ip6Addr.parse("1:2:::4"));
    try testing.expectError(Ip6AddrParseError.EmptySegment, Ip6Addr.parse("1:2::.1.2.3"));
    try testing.expectError(Ip6AddrParseError.EmptySegment, Ip6Addr.parse("1:2::3:"));


    // multiple '::'
    try testing.expectError(Ip6AddrParseError.MultipleEllipses, Ip6Addr.parse("1::2:3::4"));
    try testing.expectError(Ip6AddrParseError.MultipleEllipses, Ip6Addr.parse("::1:2::"));

    // overflow
    try testing.expectError(Ip6AddrParseError.Overflow, Ip6Addr.parse("::1cafe"));

    // invalid characters
    try testing.expectError(Ip6AddrParseError.InvalidCharacter, Ip6Addr.parse("cafe:xafe::1"));
    try testing.expectError(Ip6AddrParseError.InvalidCharacter, Ip6Addr.parse("cafe;cafe::1"));

    // incorrectly embedded ip4
    try testing.expectError(Ip6AddrParseError.EmbeddedIp4InvalidLocation, Ip6Addr.parse("1:1.2.3.4"));
    try testing.expectError(Ip6AddrParseError.EmbeddedIp4InvalidLocation, Ip6Addr.parse("1:2:3:4:5:6:7:1.2.3.4"));

    // bad embedded ip4
    try testing.expectError(Ip6AddrParseError.EmbeddedIp4InvalidFormat, Ip6Addr.parse("1::1.300.3.4"));
    try testing.expectError(Ip6AddrParseError.EmbeddedIp4InvalidFormat, Ip6Addr.parse("1::1.200."));
    try testing.expectError(Ip6AddrParseError.EmbeddedIp4InvalidFormat, Ip6Addr.parse("1::1.1.1"));

    // too many segments
    try testing.expectError(Ip6AddrParseError.TooManySegments, Ip6Addr.parse("1:2:3:4:5:6:7:8:9:10"));
    try testing.expectError(Ip6AddrParseError.TooManySegments, Ip6Addr.parse("1:2:3:4:5::6:7:8:9:10"));
    
    // not enough segments
    try testing.expectError(Ip6AddrParseError.NotEnoughSegments, Ip6Addr.parse("1:2:3"));
    try testing.expectError(Ip6AddrParseError.NotEnoughSegments, Ip6Addr.parse("cafe:dead:beef"));
    try testing.expectError(Ip6AddrParseError.NotEnoughSegments, Ip6Addr.parse("beef"));

    // ambiguous ellipsis
    try testing.expectError(Ip6AddrParseError.AmbiguousEllipsis, Ip6Addr.parse("1:2:3:4::5:6:7:8"));
}

test "Ip4 Address/get" {
    const addr = Ip4Addr.fromArray(u8, [_]u8{ 192, 168, 30, 15 });

    try testing.expectEqual(@as(u8, 168), addr.get(u8, 1));
    try testing.expectEqual(@as(u16, 0x1e0f), addr.get(u16, 1));
}

test "Ip6 Address/get" {
    const addr = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef });

    try testing.expectEqual(@as(u8, 0xb8), addr.get(u8, 3));
    try testing.expectEqual(@as(u16, 0x89ab), addr.get(u16, 6));
}

test "Ip4 Address/convert to and from std.net.Ip4Address" {
    // 192 168 73 79 <-> c0 a8 49 4f
    const value: u32 = 0xc0a8494f;
    const sys_addr = try net.Ip4Address.parse("192.168.73.79", 0);

    const addr = Ip4Addr.fromNetAddress(sys_addr);
    try testing.expectEqual(value, addr.value());
    try testing.expectEqual(sys_addr.sa.addr, addr.toNetAddress().sa.addr);
}

test "Ip6 Address/convert to and from std.net.Ip6Address" {
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const sys_addr = try net.Ip6Address.parse("2001:db8::89ab:cdef", 0);

    const addr = Ip6Addr.fromNetAddress(sys_addr);
    try testing.expectEqual(value, addr.value());
    try testing.expectEqual(sys_addr.sa.addr, addr.toNetAddress().sa.addr);
}

test "Ip4 Address/convert to Ip6 Address" {
    const value: u32 = 0xc0a8494f;
    const eq_value: u128 = 0x00ffffc0a8494f;
    try testing.expectEqual(eq_value, Ip4Addr.fromArray(u32, [_]u32{value}).toIp6().value());
}

test "Ip6 Address/convert to Ip4 Address" {
    const value: u128 = 0x00ffffc0a8494f;
    const eq_value: u32 = 0xc0a8494f;
    try testing.expectEqual(eq_value, Ip6Addr.fromArray(u128, [_]u128{value}).toIp4().?.value());

    const value1: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    try testing.expect(Ip6Addr.fromArray(u128, [_]u128{value1}).toIp4() == null);
}

test "Ip4 Address/format" {
    try testing.expectFmt("192.168.73.72", "{}", .{try Ip4Addr.parse("192.168.73.72")});
    try testing.expectFmt("c0.a8.49.1", "{x}", .{try Ip4Addr.parse("192.168.73.1")});
    try testing.expectFmt("c0.a8.01.01", "{X}", .{try Ip4Addr.parse("192.168.1.1")});
    try testing.expectFmt("11000000.10101000.1001001.1001000", "{b}", .{try Ip4Addr.parse("192.168.73.72")});
    try testing.expectFmt("11000000.10101000.01001001.01001000", "{B}", .{try Ip4Addr.parse("192.168.73.72")});
}

test "Ip6 Address/format" {
    try testing.expectFmt("2001:db8::89ab:cdef", "{}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});

    try testing.expectFmt("2001:db8::89ab:cdef", "{x}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:db8:0:0:0:0:89ab:cdef", "{xE}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:0db8::89ab:cdef", "{X}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:0db8:0000:0000:0000:0000:89ab:cdef", "{XE}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});

    try testing.expectFmt("10000000000001:110110111000::11", "{b}", .{try Ip6Addr.parse("2001:db8::3")});
    try testing.expectFmt("10000000000001:110110111000:0:0:0:0:0:11", "{bE}", .{try Ip6Addr.parse("2001:db8::3")});
    try testing.expectFmt("0010000000000001:0000110110111000::0000000000000011", "{B}", .{try Ip6Addr.parse("2001:db8::3")});
}
