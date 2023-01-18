const std = @import("std");

const builtin = std.builtin;
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const net = std.net;
const testing = std.testing;

const addrlib = @import("./addr_value.zig");
const util = @import("./utils.zig");
const v4 = @import("./ip4addr.zig");

pub const ParseError = error{
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

/// IPv6 parsing errors.
pub const Addr = packed struct {
    const Self = @This();
    /// The underlying ValueType of the wrapped value.
    pub const ValueType = addrlib.AddrValue(u128);

    addr: ValueType,

    /// Create an Addr directly from the value.
    pub fn init(v: u128) Self {
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

    /// Create an address from the std.net.Ip6Address.
    /// The conversion is lossy and all information except the address itself
    /// is discarded.
    pub fn fromNetAddress(a: net.Ip6Address) Self {
        const bs = @ptrCast(*const [16]u8, &a.sa.addr);
        return fromArray(u8, bs.*);
    }

    /// Parse the address from the string representation.
    /// The method supports only the standard representation of the
    /// IPv6 address WITHOUT the zone identifier.
    /// Use a separate type for dealing with scoped addresses.
    pub fn parse(input: []const u8) ParseError!Self {
        // parsing strategy is almost identical to https://pkg.go.dev/net/netip

        var s: []const u8 = input[0..];
        var addr: [8]u16 = [_]u16{0} ** 8;
        var ellipsis: ?usize = null;

        if (s.len >= 2 and s[0] == ':' and s[1] == ':') {
            ellipsis = 0;
            s = s[2..];
            if (s.len == 0) {
                return Addr{ .addr = ValueType{ .v = 0 } };
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

                        acc = math.shlExact(u16, acc, 4) catch return ParseError.Overflow;
                        acc += d;
                    },
                    '.', ':' => break,
                    else => return ParseError.InvalidCharacter,
                }
            }

            if (chunk_end == 0) {
                return ParseError.EmptySegment;
            }

            // check if this is an embedded v4 address
            if (chunk_end < s.len and s[chunk_end] == '.') {
                if ((ellipsis == null and addr_i != 6) or addr_i > 6) {
                    // wrong position to insert 4 bytes of the embedded ip4
                    return ParseError.EmbeddedIp4InvalidLocation;
                }

                // discard the acc and parse the whole fragment as v4
                const ip4 = v4.Addr.parse(s[0..]) catch return ParseError.EmbeddedIp4InvalidFormat;
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
            assert(s[0] == ':');
            if (s.len == 1) {
                return ParseError.EmptySegment;
            }
            s = s[1..];

            // check one more char in case it's ellipsis '::'
            if (s[0] == ':') {
                if (ellipsis) |_| {
                    return ParseError.MultipleEllipses;
                }

                ellipsis = filled;
                s = s[1..];
                if (s.len == 0) {
                    break;
                }
            }
        }

        if (s.len != 0) {
            return ParseError.TooManySegments;
        }

        if (filled < addr.len) {
            if (ellipsis) |e| {
                const zs = addr.len - filled;
                mem.copyBackwards(u16, addr[e + zs .. addr.len], addr[e..filled]);
                mem.set(u16, addr[e .. e + zs], 0);
            } else {
                return ParseError.NotEnoughSegments;
            }
        } else if (ellipsis) |_| {
            return ParseError.AmbiguousEllipsis;
        }

        return fromArray(u16, addr);
    }

    /// Returns the underlying address value.
    pub fn value(self: Addr) u128 {
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
    pub fn toNetAddress(self: Self, port: u16) net.Ip6Address {
        return net.Ip6Address.init(self.toArray(u8), port, 0, 0);
    }

    /// Return an equivalent IPv4 address if the current address
    /// is IPv4-mapped in the '::ffff:0:0/96'.
    pub fn toIp4(self: Self) ?v4.Addr {
        if (self.addr.v >> 32 != 0xffff) {
            return null;
        }

        return v4.Addr.fromArray(u32, [_]u32{@truncate(u32, self.addr.v)});
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
                        util.invalidFmtErr(fmt, Self);
                    }

                    mode.expand = true;
                },
                'x', 'X', 'b', 'B' => {
                    if (mode_set) {
                        util.invalidFmtErr(fmt, Self);
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
                else => util.invalidFmtErr(fmt, Self),
            }
        }

        return mode;
    }

    /// Print the address. A number of non-standard (e.g. non-empty)
    /// modifiers are supported:
    ///  * x - will print all octets as hex numbers (that's the default).
    ///  * X - will do the same as 'x', but will also ensure that each value is padded.
    ///  * b - will print all octets as binary numbers instead of base-10.
    ///  * B - will do the same as 'b', but will also ensure that each value is padded.
    ///  * E - will print the address in the extended format (without ellipses '::').
    /// 'E' modifier can be used with one of the other ones, e.g. like 'xE' or 'BE'.
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

test "Ip6 Address/sizeOf" {
    try testing.expectEqual(@sizeOf(u128), @sizeOf(Addr));
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

    try testing.expectEqual(expected, Addr.fromArrayNetOrder(u8, input_u8).value());
    try testing.expectEqual(expected, Addr.fromArray(u8, input_u8).value());
    try testing.expectEqual(expected, Addr.fromArrayNetOrder(u16, input_u16_net).value());
    try testing.expectEqual(expected, Addr.fromArray(u16, input_u16_native).value());
}

test "Ip6 Address/toArrayX" {
    // 2001:db8::89ab:cdef
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const addr = Addr.init(value);
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

test "Ip6 Address/Parse" {
    const comp_time_one = comptime try Addr.parse("::1");

    // compile time test
    try testing.expectEqual(@as(u128, 1), comp_time_one.value());

    // format tests
    try testing.expectEqual(Addr.init(0), (try Addr.parse("::")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("0:0::0:0")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("::0:0:0")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("0:0:0::")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("0:0:0:0::0:0:0")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("0:0:0:0:0:0:0:0")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("0:0:0:0:0:0:0.0.0.0")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("::0.0.0.0")));
    try testing.expectEqual(Addr.init(0), (try Addr.parse("0:0::0.0.0.0")));

    // value tests
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }),
        (try Addr.parse("1:2:3:4:5:6:7:8")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x0, 0x6, 0x7, 0x8 }),
        (try Addr.parse("1:2:3:4::6:7:8")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x0, 0x0, 0x6, 0x7, 0x8 }),
        (try Addr.parse("1:2:3::6:7:8")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x7, 0x8 }),
        (try Addr.parse("::6:7:8")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 }),
        (try Addr.parse("1:2:3::")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8 }),
        (try Addr.parse("::8")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }),
        (try Addr.parse("1::")),
    );

    // embedded ipv4
    try testing.expectEqual(
        Addr.fromArray(u8, [_]u8{ 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa, 0xb, 0xc, 0xd }),
        (try Addr.parse("100::10.11.12.13")),
    );
    try testing.expectEqual(
        Addr.fromArray(u8, [_]u8{ 0, 0x1, 0, 0x2, 0, 0x3, 0, 0x4, 0, 0x5, 0, 0x6, 0xa, 0xb, 0xc, 0xd }),
        (try Addr.parse("1:2:3:4:5:6:10.11.12.13")),
    );

    // larger numbers
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef }),
        (try Addr.parse("2001:db8::89ab:cdef")),
    );
    try testing.expectEqual(
        Addr.fromArray(u16, [_]u16{ 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff }),
        (try Addr.parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
    );

    // empty or ambiguous segments
    try testing.expectError(ParseError.EmptySegment, Addr.parse(":::"));
    try testing.expectError(ParseError.EmptySegment, Addr.parse(":"));
    try testing.expectError(ParseError.EmptySegment, Addr.parse("1:2:::4"));
    try testing.expectError(ParseError.EmptySegment, Addr.parse("1:2::.1.2.3"));
    try testing.expectError(ParseError.EmptySegment, Addr.parse("1:2::3:"));

    // multiple '::'
    try testing.expectError(ParseError.MultipleEllipses, Addr.parse("1::2:3::4"));
    try testing.expectError(ParseError.MultipleEllipses, Addr.parse("::1:2::"));

    // overflow
    try testing.expectError(ParseError.Overflow, Addr.parse("::1cafe"));

    // invalid characters
    try testing.expectError(ParseError.InvalidCharacter, Addr.parse("cafe:xafe::1"));
    try testing.expectError(ParseError.InvalidCharacter, Addr.parse("cafe;cafe::1"));

    // incorrectly embedded ip4
    try testing.expectError(ParseError.EmbeddedIp4InvalidLocation, Addr.parse("1:1.2.3.4"));
    try testing.expectError(ParseError.EmbeddedIp4InvalidLocation, Addr.parse("1:2:3:4:5:6:7:1.2.3.4"));

    // bad embedded ip4
    try testing.expectError(ParseError.EmbeddedIp4InvalidFormat, Addr.parse("1::1.300.3.4"));
    try testing.expectError(ParseError.EmbeddedIp4InvalidFormat, Addr.parse("1::1.200."));
    try testing.expectError(ParseError.EmbeddedIp4InvalidFormat, Addr.parse("1::1.1.1"));

    // too many segments
    try testing.expectError(ParseError.TooManySegments, Addr.parse("1:2:3:4:5:6:7:8:9:10"));
    try testing.expectError(ParseError.TooManySegments, Addr.parse("1:2:3:4:5::6:7:8:9:10"));

    // not enough segments
    try testing.expectError(ParseError.NotEnoughSegments, Addr.parse("1:2:3"));
    try testing.expectError(ParseError.NotEnoughSegments, Addr.parse("cafe:dead:beef"));
    try testing.expectError(ParseError.NotEnoughSegments, Addr.parse("beef"));

    // ambiguous ellipsis
    try testing.expectError(ParseError.AmbiguousEllipsis, Addr.parse("1:2:3:4::5:6:7:8"));
}

test "Ip6 Address/get" {
    const addr = Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef });

    try testing.expectEqual(@as(u8, 0xb8), addr.get(u8, 3));
    try testing.expectEqual(@as(u16, 0x89ab), addr.get(u16, 6));
}

test "Ip6 Address/convert to and from std.net.Address" {
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const sys_addr = try net.Ip6Address.parse("2001:db8::89ab:cdef", 0);

    const addr = Addr.fromNetAddress(sys_addr);
    try testing.expectEqual(value, addr.value());
    try testing.expectEqual(sys_addr.sa.addr, addr.toNetAddress(10).sa.addr);
}

test "Ip6 Address/convert to Ip4 Address" {
    const value: u128 = 0x00ffffc0a8494f;
    const eq_value: u32 = 0xc0a8494f;
    try testing.expectEqual(eq_value, Addr.init(value).toIp4().?.value());

    const value1: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    try testing.expect(Addr.init(value1).toIp4() == null);
}

test "Ip6 Address/format" {
    try testing.expectFmt("2001:db8::89ab:cdef", "{}", .{try Addr.parse("2001:db8::89ab:cdef")});

    try testing.expectFmt("2001:db8::89ab:cdef", "{x}", .{try Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:db8:0:0:0:0:89ab:cdef", "{xE}", .{try Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:0db8::89ab:cdef", "{X}", .{try Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:0db8:0000:0000:0000:0000:89ab:cdef", "{XE}", .{try Addr.parse("2001:db8::89ab:cdef")});

    try testing.expectFmt("10000000000001:110110111000::11", "{b}", .{try Addr.parse("2001:db8::3")});
    try testing.expectFmt("10000000000001:110110111000:0:0:0:0:0:11", "{bE}", .{try Addr.parse("2001:db8::3")});
    try testing.expectFmt("0010000000000001:0000110110111000::0000000000000011", "{B}", .{try Addr.parse("2001:db8::3")});
}
