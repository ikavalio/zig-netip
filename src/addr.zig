const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const net = std.net;
const os = std.os;
const testing = std.testing;

// common address format options
const FormatMode = struct {
    fmt: []const u8,
    expand: bool,
};

fn invalidFmtErr(comptime fmt: []const u8, comptime value: type) void {
    @compileError("invalid format string '" ++ fmt ++ "' for type '" ++ @typeName(value) ++ "'");
}

// ipv4 mixin functions and constants
const ip4 = struct {
    const BaseType = u32;
    const StdlibType = net.Ip4Address;
    const ParseElementType = u8;
    const PrintElementType = u8;
    const ParseError = error{
        InvalidCharacter,
        LeadingZero,
        EmptyOctet,
        TooManyOctets,
        NotEnoughOctets,
        Overflow,
    };

    inline fn convertToStdlibAddress(v: [@sizeOf(BaseType)]u8, port: u16) StdlibType {
        return StdlibType.init(v, port);
    }

    inline fn parse(s: []const u8) ParseError![@sizeOf(BaseType) / @sizeOf(ParseElementType)]ParseElementType {
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

        return octs;
    }

    inline fn format(
        comptime mode: FormatMode,
        bs: [@sizeOf(BaseType) / @sizeOf(PrintElementType)]PrintElementType,
        out_stream: anytype,
    ) !void {
        const blk = "{" ++ mode.fmt ++ "}";
        const fmt_expr = blk ++ ("." ++ blk) ** 3;

        try std.fmt.format(out_stream, fmt_expr, .{
            bs[0],
            bs[1],
            bs[2],
            bs[3],
        });
    }
};

// ipv6 mixin function and constaints
const ip6 = struct {
    const BaseType = u128;
    const StdlibType = std.net.Ip6Address;
    const ParseElementType = u16;
    const PrintElementType = u16;
    const ParseError = error{
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

    inline fn convertToStdlibAddress(v: [@sizeOf(BaseType)]u8, port: u16) StdlibType {
        return StdlibType.init(v, port, 0, 0);
    }

    inline fn parse(input: []const u8) ParseError![@sizeOf(BaseType) / @sizeOf(ParseElementType)]ParseElementType {
        // parsing strategy is almost identical to https://pkg.go.dev/net/netip

        var s: []const u8 = input[0..];
        var addr: [8]u16 = [_]u16{0} ** 8;
        var ellipsis: ?usize = null;

        if (s.len >= 2 and s[0] == ':' and s[1] == ':') {
            ellipsis = 0;
            s = s[2..];
            if (s.len == 0) {
                return addr;
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
                const segs = ip4.parse(s[0..]) catch return ParseError.EmbeddedIp4InvalidFormat;
                addr[addr_i] = (@as(u16, segs[0]) << 8) | @as(u16, segs[1]);
                addr[addr_i + 1] = (@as(u16, segs[2]) << 8) | @as(u16, segs[3]);
                filled += 2;
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

        return addr;
    }

    inline fn format(
        comptime mode: FormatMode,
        segs: [@sizeOf(BaseType) / @sizeOf(PrintElementType)]PrintElementType,
        out_stream: anytype,
    ) !void {
        const fmt_seg = "{" ++ (if (mode.fmt.len == 0) "x" else mode.fmt) ++ "}";

        var zero_start: usize = 255;
        var zero_end: usize = 255;

        var i: usize = 0;
        while (i < segs.len) : (i += 1) {
            var j = i;
            while (j < segs.len and segs[j] == 0) : (j += 1) {}
            var l = j - i;
            if (l > 1 and l > zero_end - zero_start) {
                zero_start = i;
                zero_end = j;
            }
            i = j;
        }

        i = 0;
        while (i < segs.len) : (i += 1) {
            if (!mode.expand and i == zero_start) {
                try out_stream.writeAll("::");
                i = zero_end;
                if (i >= segs.len) {
                    break;
                }
            } else if (i > 0) {
                try out_stream.writeAll(":");
            }

            try std.fmt.format(out_stream, fmt_seg, .{segs[i]});
        }
    }
};

/// An Addr type constructor representing the IP address as a native-order integer.
pub fn AddrForValue(comptime M: type) type {
    if (M != ip4 and M != ip6) {
        @compileError("unknown address mixin type '" ++ @typeName(M) ++ "' (only ip4 and ip6 are supported)");
    }

    return packed struct {
        const Self = @This();
        const Mixin = M;

        /// The internal type of the address.
        pub const ValueType = M.BaseType;
        /// The integer type that can be used in shl/shr instructions
        /// The type can store any bit index of the parent type.
        pub const PositionType = math.Log2Int(ValueType);
        /// The equivalent std.net Address type.
        pub const StdlibType = M.StdlibType;
        /// Parse errors enum.
        pub const ParseError = M.ParseError;
        /// The byte size of the parent type.
        pub const byte_size = @sizeOf(ValueType);

        /// Raw native-order integer value that encodes the type.
        v: ValueType,

        /// Wrap a native-order integer value into AddrValue.
        pub fn init(v: ValueType) Self {
            return Self{ .v = v };
        }

        /// Create an AddrValue from the array of arbitrary integer values.
        /// Elements of the array are ordered in the network order (most-significant first).
        /// Each integer value has the network byte order.
        pub fn fromArrayNetOrder(comptime E: type, a: [byte_size / @sizeOf(E)]E) Self {
            const p = @ptrCast(*align(@alignOf(u8)) const [byte_size / @sizeOf(u8)]u8, &a);
            const v = mem.bigToNative(ValueType, mem.bytesToValue(ValueType, p));
            return Self{ .v = v };
        }

        /// Create an AddrValue from the array of arbitrary integer values.
        /// Elements of the array are ordered in the network order (most-significant first).
        /// Each integer value has the native byte order.
        pub fn fromArray(comptime E: type, a: [byte_size / @sizeOf(E)]E) Self {
            var v: ValueType = 0;

            inline for (a) |b, i| {
                v |= @as(ValueType, b) << (@bitSizeOf(E) * ((byte_size / @sizeOf(E)) - 1 - i));
            }

            return Self{ .v = v };
        }

        /// Create an address from the associated stdlib type.
        /// The conversion is lossy and the port information
        /// is discarded.
        pub fn fromNetAddress(a: StdlibType) Self {
            const bs = @ptrCast(*const [byte_size]u8, &a.sa.addr);
            return fromArrayNetOrder(u8, bs.*);
        }

        /// Parse the address from the string representation.
        /// The method supports only the standard representation of the
        /// IPv6 address WITHOUT the zone identifier.
        /// Use a separate type for dealing with scoped addresses.
        pub fn parse(input: []const u8) ParseError!Self {
            const res = try M.parse(input);
            return fromArray(M.ParseElementType, res);
        }

        /// Returns the underlying address value.
        pub fn value(self: Self) ValueType {
            return self.v;
        }

        /// Convert the AddrValue to an array of generic integer values.
        /// Elements of the array are ordered in the network order (most-significant first).
        /// Each integer value has the network byte order.
        pub fn toArrayNetOrder(self: Self, comptime E: type) [byte_size / @sizeOf(E)]E {
            var a = self.toArray(E);

            inline for (a) |b, i| {
                a[i] = mem.nativeToBig(E, b);
            }

            return a;
        }

        /// Convert the address to an array of generic integer values.
        /// Elemenets of the array is ordered in the network order (most-significant first).
        /// Each integer value has the native byte order.
        pub fn toArray(self: Self, comptime E: type) [byte_size / @sizeOf(E)]E {
            var a: [byte_size / @sizeOf(E)]E = undefined;

            inline for (a) |_, i| {
                a[i] = self.get(E, i);
            }

            return a;
        }

        /// Convert the address to the corresponding stdlib equivalent.
        /// Since the value doesn't carry port information,
        /// it must be provided as an argument.
        pub fn toNetAddress(self: Self, port: u16) StdlibType {
            return M.convertToStdlibAddress(self.toArrayNetOrder(u8), port);
        }

        /// Get an arbitrary integer value from the address.
        /// The value always has the native byte order.
        pub fn get(self: Self, comptime E: type, i: PositionType) E {
            return @truncate(E, self.v >> (@bitSizeOf(E) * (byte_size / @sizeOf(E) - 1 - i)));
        }

        fn formatMode(comptime fmt: []const u8) FormatMode {
            var mode = FormatMode{ .fmt = "", .expand = false };
            var mode_set = false;

            inline for (fmt) |f| {
                switch (f) {
                    'E' => {
                        if (mode.expand) invalidFmtErr(fmt, Self);

                        mode.expand = true;
                    },
                    'x', 'X', 'b', 'B' => {
                        if (mode_set) invalidFmtErr(fmt, Self);

                        mode.fmt = switch (f) {
                            'x' => "x", // hex
                            'X' => "x:0>" ++ std.fmt.comptimePrint("{}", .{@sizeOf(M.PrintElementType) * 2}), // padded hex
                            'b' => "b", // bin
                            'B' => "b:0>" ++ std.fmt.comptimePrint("{}", .{@sizeOf(M.PrintElementType) * 8}), // padded bin
                            else => unreachable,
                        };

                        mode_set = true;
                    },
                    else => invalidFmtErr(fmt, Self),
                }
            }

            return mode;
        }

        /// Print the address. A number of non-standard (e.g. non-empty)
        /// modifiers are supported:
        ///  * x - will print all octets as hex numbers (that's the default for IPv6).
        ///  * X - will do the same as 'x', but will also ensure that each value is padded.
        ///  * b - will print all octets as binary numbers instead of base-10.
        ///  * B - will do the same as 'b', but will also ensure that each value is padded.
        ///  * E - will print the IPv6 address in the extended format (without ellipses '::').
        /// 'E' modifier can be used with one of the other ones, e.g. like 'xE' or 'BE'.
        pub fn format(
            self: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            out_stream: anytype,
        ) !void {
            _ = options;
            try M.format(formatMode(fmt), self.toArray(M.PrintElementType), out_stream);
        }

        /// Compare two addresses.
        pub fn order(self: Self, other: Self) math.Order {
            return math.order(self.value(), other.value());
        }

        /// Convert between IPv4 and IPv6 addresses
        /// Use '::ffff:0:0/96' for IPv4 mapped addresses.
        pub fn as(self: Self, comptime O: type) ?O {
            if (Self == O) {
                return self;
            }

            return switch (O.Mixin) {
                ip6 => O.init(0xffff00000000 | @as(O.ValueType, self.v)),
                ip4 => if (self.v >> @bitSizeOf(O.ValueType) == 0xffff) O.init(@truncate(O.ValueType, self.v)) else null,
                else => @compileError("unsupported address conversion from '" ++ @typeName(Self) ++ "' to '" ++ @typeName(O) + "'"),
            };
        }
    };
}

pub const Ip4Addr = AddrForValue(ip4);
pub const Ip6Addr = AddrForValue(ip6);

pub const Ip6AddrScoped = struct {
    pub const ParseError = error{EmptyZone} || Ip6Addr.ParseError;
    pub const NetAddrScopeError = std.fmt.BufPrintError;

    addr: Ip6Addr,
    zone: []const u8, // not owned, zone.len == 0 for zoneless ips

    /// Tie the address to the scope
    pub fn init(addr: Ip6Addr, zn: []const u8) Ip6AddrScoped {
        return Ip6AddrScoped{ .addr = addr, .zone = zn };
    }

    /// Parse the address from the string representation.
    /// The method supports only the standard representation of the
    /// IPv6 address with or without the zone identifier.
    /// The returned scope (if exists) is a slice of the input (not owned).
    pub fn parse(input: []const u8) ParseError!Ip6AddrScoped {
        const b = if (mem.indexOfScalar(u8, input, '%')) |i| i else input.len;
        const addr = try Ip6Addr.parse(input[0..b]);
        return switch (input.len - b) {
            0 => init(addr, input[b..]),
            1 => ParseError.EmptyZone,
            else => init(addr, input[b + 1 ..]),
        };
    }

    /// Create an address from the std.net.Ip6Address type.
    /// The conversion is lossy and the port information
    /// is discarded.
    /// Numeric scope_id is converted into the string (1 -> "1").
    pub fn fromNetAddress(a: net.Ip6Address, buf: []u8) NetAddrScopeError!Ip6AddrScoped {
        const addr = Ip6Addr.fromNetAddress(a);
        const zone = try std.fmt.bufPrint(buf, "{}", .{a.sa.scope_id});
        return init(addr, zone);
    }

    /// Returns true if the zone is present.
    pub fn hasZone(self: Ip6AddrScoped) bool {
        return self.zone.len > 0;
    }

    /// Print the address.
    pub fn format(
        self: Ip6AddrScoped,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        try self.addr.format(fmt, options, out_stream);
        if (self.hasZone()) {
            try std.fmt.format(out_stream, "%{s}", .{self.zone});
        }
    }
};

pub const AddrType = enum {
    v4,
    v6,
};

/// A union type that allows to work with both address types at the same time.
/// Only high-level operations are supported. Unwrap the concrete
/// prefix type to do any sort of low-level or bit operations.
pub const Addr = union(AddrType) {
    v4: Ip4Addr,
    v6: Ip6Addr,

    pub const ParseError = error{UnknownAddress} || Ip4Addr.ParseError || Ip6Addr.ParseError;

    pub fn init4(a: Ip4Addr) Addr {
        return Addr{ .v4 = a };
    }

    pub fn init6(a: Ip6Addr) Addr {
        return Addr{ .v6 = a };
    }

    /// Parse the address from the string representation
    pub fn parse(s: []const u8) ParseError!Addr {
        for (s) |c| {
            switch (c) {
                '.' => return Addr{ .v4 = try Ip4Addr.parse(s) },
                ':' => return Addr{ .v6 = try Ip6Addr.parse(s) },
                else => continue,
            }
        }

        return ParseError.UnknownAddress;
    }

    /// Create an Addr from the std.net.Address.
    /// The conversion is lossy and some information
    /// is discarded.
    pub fn fromNetAddress(a: std.net.Address) ?Addr {
        return switch (a.any.family) {
            os.AF.INET => Addr{ .v4 = Ip4Addr.fromNetAddress(a.in) },
            os.AF.INET6 => Addr{ .v6 = Ip6Addr.fromNetAddress(a.in6) },
            else => null,
        };
    }

    /// Return the equivalent IPv6 address.
    pub fn as6(self: Addr) Addr {
        return switch (self) {
            .v4 => |a| Addr{ .v6 = a.as(Ip6Addr).? },
            .v6 => self,
        };
    }

    /// Return the equivalent IPv4 address if it exists.
    pub fn as4(self: Addr) ?Addr {
        return switch (self) {
            .v4 => self,
            .v6 => |a| (if (a.as(Ip4Addr)) |p| Addr{ .v4 = p } else null),
        };
    }

    /// Print the address. The modifier is passed to either Ip4Addr or Ip6Addr unchanged.
    pub fn format(
        self: Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        switch (self) {
            .v4 => |a| try a.format(fmt, options, out_stream),
            .v6 => |a| try a.format(fmt, options, out_stream),
        }
    }

    /// Convert the address to the equivalent std.net.Address.
    /// Since the value doesn't carry port information,
    /// it must be provided as an argument.
    pub fn toNetAddress(self: Addr, port: u16) std.net.Address {
        return switch (self) {
            .v4 => |a| std.net.Address{ .in = a.toNetAddress(port) },
            .v6 => |a| std.net.Address{ .in6 = a.toNetAddress(port) },
        };
    }

    /// Compare two addresses. IPv4 is always less than IPv6
    pub fn order(self: Addr, other: Addr) math.Order {
        return switch (self) {
            .v4 => |l4| switch (other) {
                .v4 => |r4| l4.order(r4),
                .v6 => math.Order.lt,
            },
            .v6 => |l6| switch (other) {
                .v4 => math.Order.gt,
                .v6 => |r6| l6.order(r6),
            },
        };
    }
};

test "Ip6 Address/sizeOf" {
    try testing.expectEqual(@sizeOf(u128), @sizeOf(Ip6Addr));
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

test "Ip6 Address/toArrayX" {
    // 2001:db8::89ab:cdef
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const addr = Ip6Addr.init(value);
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
    try testing.expectEqual(@as(u128, 1), comp_time_one.v6.value());

    // format tests
    try testing.expectEqual(Ip6Addr.init(0), (try Ip6Addr.parse("::")));
    try testing.expectEqual(Ip6Addr.init(0), (try Ip6Addr.parse("0:0::0:0")));
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("::0:0:0")).v6);
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("0:0:0::")).v6);
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("0:0:0:0::0:0:0")).v6);
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("0:0:0:0:0:0:0:0")).v6);
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("0:0:0:0:0:0:0.0.0.0")).v6);
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("::0.0.0.0")).v6);
    try testing.expectEqual(Ip6Addr.init(0), (try Addr.parse("0:0::0.0.0.0")).v6);

    // value tests
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 }),
        (try Ip6Addr.parse("1:2:3:4:5:6:7:8")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x4, 0x0, 0x6, 0x7, 0x8 }),
        (try Addr.parse("1:2:3:4::6:7:8")).v6,
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x0, 0x0, 0x6, 0x7, 0x8 }),
        (try Addr.parse("1:2:3::6:7:8")).v6,
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, 0x7, 0x8 }),
        (try Addr.parse("::6:7:8")).v6,
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0 }),
        (try Addr.parse("1:2:3::")).v6,
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8 }),
        (try Addr.parse("::8")).v6,
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u16, [_]u16{ 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }),
        (try Addr.parse("1::")).v6,
    );

    // embedded ipv4
    try testing.expectEqual(
        Ip6Addr.fromArray(u8, [_]u8{ 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa, 0xb, 0xc, 0xd }),
        (try Ip6Addr.parse("100::10.11.12.13")),
    );
    try testing.expectEqual(
        Ip6Addr.fromArray(u8, [_]u8{ 0, 0x1, 0, 0x2, 0, 0x3, 0, 0x4, 0, 0x5, 0, 0x6, 0xa, 0xb, 0xc, 0xd }),
        (try Addr.parse("1:2:3:4:5:6:10.11.12.13")).v6,
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
    try testing.expectError(Addr.ParseError.EmptySegment, Addr.parse(":::"));
    try testing.expectError(Addr.ParseError.EmptySegment, Addr.parse(":"));
    try testing.expectError(Addr.ParseError.EmptySegment, Addr.parse("1:2:::4"));
    try testing.expectError(Addr.ParseError.EmptySegment, Addr.parse("1:2::.1.2.3"));
    try testing.expectError(Ip6Addr.ParseError.EmptySegment, Ip6Addr.parse("1:2::3:"));

    // multiple '::'
    try testing.expectError(Addr.ParseError.MultipleEllipses, Addr.parse("1::2:3::4"));
    try testing.expectError(Addr.ParseError.MultipleEllipses, Addr.parse("::1:2::"));

    // overflow
    try testing.expectError(Addr.ParseError.Overflow, Addr.parse("::1cafe"));

    // invalid characters
    try testing.expectError(Ip6Addr.ParseError.InvalidCharacter, Ip6Addr.parse("cafe:xafe::1"));
    try testing.expectError(Ip6Addr.ParseError.InvalidCharacter, Ip6Addr.parse("cafe;cafe::1"));

    // incorrectly embedded ip4
    try testing.expectError(Ip6Addr.ParseError.EmbeddedIp4InvalidLocation, Ip6Addr.parse("1:1.2.3.4"));
    try testing.expectError(Ip6Addr.ParseError.EmbeddedIp4InvalidLocation, Ip6Addr.parse("1:2:3:4:5:6:7:1.2.3.4"));

    // bad embedded ip4
    try testing.expectError(Ip6Addr.ParseError.EmbeddedIp4InvalidFormat, Ip6Addr.parse("1::1.300.3.4"));
    try testing.expectError(Ip6Addr.ParseError.EmbeddedIp4InvalidFormat, Ip6Addr.parse("1::1.200."));
    try testing.expectError(Ip6Addr.ParseError.EmbeddedIp4InvalidFormat, Ip6Addr.parse("1::1.1.1"));

    // too many segments
    try testing.expectError(Ip6Addr.ParseError.TooManySegments, Ip6Addr.parse("1:2:3:4:5:6:7:8:9:10"));
    try testing.expectError(Ip6Addr.ParseError.TooManySegments, Ip6Addr.parse("1:2:3:4:5::6:7:8:9:10"));

    // not enough segments
    try testing.expectError(Ip6Addr.ParseError.NotEnoughSegments, Ip6Addr.parse("1:2:3"));
    try testing.expectError(Ip6Addr.ParseError.NotEnoughSegments, Ip6Addr.parse("cafe:dead:beef"));
    try testing.expectError(Ip6Addr.ParseError.NotEnoughSegments, Ip6Addr.parse("beef"));

    // ambiguous ellipsis
    try testing.expectError(Ip6Addr.ParseError.AmbiguousEllipsis, Ip6Addr.parse("1:2:3:4::5:6:7:8"));
}

test "Ip6 Address Scoped/Parse" {
    {
        const expected_addr = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef });
        const expected_zone = "eth3";
        const actual = try Ip6AddrScoped.parse("2001:db8::89ab:cdef%eth3");

        try testing.expect(actual.hasZone());
        try testing.expectEqual(expected_addr, actual.addr);
        try testing.expectEqualStrings(expected_zone, actual.zone);
    }

    {
        // the zone can be implementation specific
        const expected_addr = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef });
        const expected_zone = "eth%3";
        const actual = try Ip6AddrScoped.parse("2001:db8::89ab:cdef%eth%3");

        try testing.expect(actual.hasZone());
        try testing.expectEqual(expected_addr, actual.addr);
        try testing.expectEqualStrings(expected_zone, actual.zone);
    }

    {
        const expected_addr = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef });
        const expected_zone = "";
        const actual = try Ip6AddrScoped.parse("2001:db8::89ab:cdef");

        try testing.expect(!actual.hasZone());
        try testing.expectEqual(expected_addr, actual.addr);
        try testing.expectEqualStrings(expected_zone, actual.zone);
    }

    // raw IPv6 parsing errors
    try testing.expectError(Ip6AddrScoped.ParseError.AmbiguousEllipsis, Ip6AddrScoped.parse("1:2:3:4::5:6:7:8"));

    // empty zone
    try testing.expectError(Ip6AddrScoped.ParseError.EmptyZone, Ip6AddrScoped.parse("::1%"));
}

test "Ip6 Address/get" {
    const addr = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0x0db8, 0, 0, 0, 0, 0x89ab, 0xcdef });

    try testing.expectEqual(@as(u8, 0xb8), addr.get(u8, 3));
    try testing.expectEqual(@as(u16, 0x89ab), addr.get(u16, 6));
}

test "Ip6 Address/convert to and from std.net.Address" {
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const sys_addr = try net.Ip6Address.parse("2001:db8::89ab:cdef", 10);
    const sys_addr1 = try net.Address.parseIp6("2001:db8::89ab:cdef", 10);

    const addr = Ip6Addr.fromNetAddress(sys_addr);
    try testing.expectEqual(value, addr.value());
    try testing.expectEqual(sys_addr, addr.toNetAddress(10));

    const addr1 = Addr.fromNetAddress(sys_addr1).?;
    try testing.expectEqual(value, addr1.v6.value());
    try testing.expectEqual(sys_addr1.in6, addr1.toNetAddress(10).in6);
}

test "Ip6 Address Scoped/convert to and from std.net.Address" {
    const value: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    const sys_addr = try net.Ip6Address.parse("2001:db8::89ab:cdef%101", 10);

    {
        var buf = [_]u8{0} ** 10;
        const scoped = try Ip6AddrScoped.fromNetAddress(sys_addr, buf[0..]);
        try testing.expectEqual(value, scoped.addr.value());
        try testing.expectEqualStrings("101", scoped.zone);
    }

    {
        var buf = [_]u8{0};
        try testing.expectError(Ip6AddrScoped.NetAddrScopeError.NoSpaceLeft, Ip6AddrScoped.fromNetAddress(sys_addr, buf[0..]));
    }
}

test "Ip6 Address/convert to Ip4 Address" {
    const value: u128 = 0x00ffffc0a8494f;
    const eq_value: u32 = 0xc0a8494f;
    try testing.expectEqual(eq_value, Ip6Addr.init(value).as(Ip4Addr).?.value());
    try testing.expectEqual(
        Addr.init4(Ip4Addr.init(eq_value)),
        Addr.init6(Ip6Addr.init(value)).as4().?,
    );

    const value1: u128 = 0x2001_0db8_0000_0000_0000_0000_89ab_cdef;
    try testing.expect(null == Ip6Addr.init(value1).as(Ip4Addr));
    try testing.expect(null == Addr.init6(Ip6Addr.init(value1)).as4());
}

test "Ip6 Address/format" {
    try testing.expectFmt("2001:db8::89ab:cdef", "{}", .{try Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:db8::", "{}", .{try Addr.parse("2001:db8::")});
    try testing.expectFmt("::1", "{}", .{try Ip6Addr.parse("::1")});
    try testing.expectFmt("::", "{}", .{try Ip6Addr.parse("::")});

    try testing.expectFmt("2001:db8::89ab:cdef", "{x}", .{try Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:db8:0:0:0:0:89ab:cdef", "{xE}", .{try Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:0db8::89ab:cdef", "{X}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:0db8:0000:0000:0000:0000:89ab:cdef", "{XE}", .{try Ip6Addr.parse("2001:db8::89ab:cdef")});

    try testing.expectFmt("10000000000001:110110111000::11", "{b}", .{try Addr.parse("2001:db8::3")});
    try testing.expectFmt("10000000000001:110110111000:0:0:0:0:0:11", "{bE}", .{try Ip6Addr.parse("2001:db8::3")});
    try testing.expectFmt("0010000000000001:0000110110111000::0000000000000011", "{B}", .{try Ip6Addr.parse("2001:db8::3")});
}

test "Ip6 Address Scoped/format" {
    try testing.expectFmt("2001:db8::89ab:cdef", "{x}", .{try Ip6AddrScoped.parse("2001:db8::89ab:cdef")});
    try testing.expectFmt("2001:db8:0:0:0:0:89ab:cdef%eth0", "{xE}", .{try Ip6AddrScoped.parse("2001:db8::89ab:cdef%eth0")});
    try testing.expectFmt("2001:0db8::89ab:cdef%1", "{X}", .{try Ip6AddrScoped.parse("2001:db8::89ab:cdef%1")});
}

test "Ip6 Address/comparison" {
    const addr1 = Ip6Addr.init(1);
    const addr2 = Ip6Addr.init(2);

    try testing.expectEqual(math.Order.eq, addr1.order(addr1));
    try testing.expectEqual(math.Order.eq, addr2.order(addr2));
    try testing.expectEqual(math.Order.lt, addr1.order(addr2));
    try testing.expectEqual(math.Order.gt, addr2.order(addr1));

    try testing.expectEqual(math.Order.gt, Addr.init6(addr2).order(Addr.init6(addr1)));
    try testing.expectEqual(math.Order.gt, Addr.init6(Ip6Addr.init(0)).order(Addr.init4(Ip4Addr.init(0xffffffff))));
}

test "Ip4 Address/sizeOf" {
    try testing.expectEqual(@sizeOf(u32), @sizeOf(Ip4Addr));
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

test "Ip4 Address/toArrayX" {
    // 192 168 73 79 <-> c0 a8 49 3b
    const value: u32 = 0xc0a8493b;
    const addr = Ip4Addr.init(value);
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

    try testing.expectEqual(@as(u32, 1), comp_time_one.v4.value());

    try testing.expectEqual(
        Ip4Addr.fromArray(u8, [_]u8{ 192, 168, 30, 15 }),
        (try Addr.parse("192.168.30.15")).v4,
    );
    try testing.expectEqual(
        Ip4Addr.fromArray(u8, [_]u8{ 0, 0, 0, 0 }),
        (try Ip4Addr.parse("0.0.0.0")),
    );
    try testing.expectEqual(
        Ip4Addr.fromArray(u8, [_]u8{ 255, 255, 255, 255 }),
        (try Ip4Addr.parse("255.255.255.255")),
    );

    try testing.expectError(Ip4Addr.ParseError.NotEnoughOctets, Ip4Addr.parse(""));
    try testing.expectError(Ip4Addr.ParseError.NotEnoughOctets, Ip4Addr.parse("123"));
    try testing.expectError(Ip4Addr.ParseError.NotEnoughOctets, Ip4Addr.parse("1.1.1"));
    try testing.expectError(Ip4Addr.ParseError.InvalidCharacter, Ip4Addr.parse("20::1:1"));
    try testing.expectError(Ip4Addr.ParseError.Overflow, Ip4Addr.parse("256.1.1.1"));
    try testing.expectError(Addr.ParseError.LeadingZero, Addr.parse("254.01.1.1"));
    try testing.expectError(Addr.ParseError.EmptyOctet, Addr.parse(".1.1.1"));
    try testing.expectError(Ip4Addr.ParseError.EmptyOctet, Ip4Addr.parse("1.1..1"));
    try testing.expectError(Ip4Addr.ParseError.EmptyOctet, Ip4Addr.parse("1.1.1."));
    try testing.expectError(Ip4Addr.ParseError.TooManyOctets, Ip4Addr.parse("1.1.1.1.1"));
}

test "Ip4 Address/get" {
    const addr = Ip4Addr.fromArray(u8, [_]u8{ 192, 168, 30, 15 });

    try testing.expectEqual(@as(u8, 168), addr.get(u8, 1));
    try testing.expectEqual(@as(u16, 0x1e0f), addr.get(u16, 1));
}

test "Ip4 Address/convert to and from std.net.Ip4Address" {
    // 192 168 73 79 <-> c0 a8 49 4f
    const value: u32 = 0xc0a8494f;
    const sys_addr = try net.Ip4Address.parse("192.168.73.79", 5);
    const sys_addr1 = try net.Address.parseIp4("192.168.73.79", 5);

    const addr = Ip4Addr.fromNetAddress(sys_addr);
    try testing.expectEqual(value, addr.value());
    try testing.expectEqual(sys_addr, addr.toNetAddress(5));

    const addr1 = Addr.fromNetAddress(sys_addr1).?;
    try testing.expectEqual(value, addr1.v4.value());
    try testing.expectEqual(sys_addr1.in, addr1.toNetAddress(5).in);
}

test "Ip4 Address/convert to Ip6 Address" {
    const value: u32 = 0xc0a8494f;
    const eq_value: u128 = 0x00ffffc0a8494f;
    try testing.expectEqual(eq_value, Ip4Addr.fromArray(u32, [_]u32{value}).as(Ip6Addr).?.value());
    try testing.expectEqual(
        Addr.init6(Ip6Addr.init(eq_value)),
        Addr.init4(Ip4Addr.init(value)).as6(),
    );
}

test "Ip4 Address/format" {
    try testing.expectFmt("192.168.73.72", "{}", .{try Addr.parse("192.168.73.72")});
    try testing.expectFmt("c0.a8.49.1", "{x}", .{try Ip4Addr.parse("192.168.73.1")});
    try testing.expectFmt("c0.a8.01.01", "{X}", .{try Addr.parse("192.168.1.1")});
    try testing.expectFmt("11000000.10101000.1001001.1001000", "{b}", .{try Ip4Addr.parse("192.168.73.72")});
    try testing.expectFmt("11000000.10101000.01001001.01001000", "{B}", .{try Addr.parse("192.168.73.72")});
}

test "Ip4 Address/comparison" {
    const addr1 = Ip4Addr.init(1);
    const addr2 = Ip4Addr.init(2);

    try testing.expectEqual(math.Order.eq, addr1.order(addr1));
    try testing.expectEqual(math.Order.eq, addr2.order(addr2));
    try testing.expectEqual(math.Order.lt, addr1.order(addr2));
    try testing.expectEqual(math.Order.gt, addr2.order(addr1));

    try testing.expectEqual(math.Order.gt, Addr.init4(addr2).order(Addr.init4(addr1)));
    try testing.expectEqual(math.Order.lt, Addr.init4(Ip4Addr.init(0xffffffff)).order(Addr.init6(Ip6Addr.init(0))));
}
