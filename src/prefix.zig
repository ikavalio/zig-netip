const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const testing = std.testing;
const Signedness = std.builtin.Signedness;

const v4 = @import("./ip4addr.zig");
const v6 = @import("./ip6addr.zig");

// that includes the Overflow and InvalidCharacter
pub const ParseError = error{NoBitMask} || v4.ParseError || v6.ParseError;

pub fn Prefix(comptime T: type) type {
    if (T != v4.Addr and T != v6.Addr) {
        @compileError("unknown address type '" ++ @typeName(T) ++ "' (only v4 and v6 addresses are supported)");
    }

    const pos_bits = @typeInfo(T.ValueType.PositionType).Int.bits;

    return packed struct {
        const Self = @This();

        // we need an extra bit to represent the widest mask, e.g. /32 for the v4 address
        pub const MaskType = std.meta.Int(Signedness.unsigned, pos_bits + 1);
        pub const MaxMaskBits = 1 << pos_bits;

        addr: T,
        mask_bits: MaskType,

        /// Create a prefix from the given address and the number of bits.
        /// Following the go's netip implementation, we don't zero bits not
        /// covered by the mask.
        /// The mask bits size must be <= address specific MaxMaskBits.
        pub fn init(a: T, bits: MaskType) Self {
            assert(bits <= MaxMaskBits);
            return Self{ .addr = a, .mask_bits = bits };
        }

        /// Parse the prefix from the string representation
        pub fn parse(s: []const u8) ParseError!Self {
            if (mem.indexOfScalar(u8, s, '/')) |i| {
                if (i == s.len - 1) return ParseError.NoBitMask;

                const parsed = try T.parse(s[0..i]);

                var bits: MaskType = 0;
                for (s[i + 1 ..]) |c| {
                    switch (c) {
                        '0'...'9' => {
                            bits = math.mul(MaskType, bits, 10) catch return ParseError.Overflow;
                            bits = math.add(MaskType, bits, @truncate(MaskType, c - '0')) catch return ParseError.Overflow;
                        },
                        else => return ParseError.InvalidCharacter,
                    }
                }

                if (bits > MaxMaskBits) return ParseError.Overflow;

                return init(parsed, bits);
            }

            return ParseError.NoBitMask;
        }

        /// Returns underlying address.
        pub fn addr(self: Self) T {
            return self.addr;
        }

        /// Returns the number of bits in the mask
        pub fn maskBits(self: Self) MaskType {
            return self.mask_bits;
        }
    };
}

pub const Ip4Prefix = Prefix(v4.Addr);
pub const Ip6Prefix = Prefix(v6.Addr);

test "Prefix/trivial init" {
    const addr4 = v4.Addr.init(1);
    const addr6 = v6.Addr.init(2);

    try testing.expectEqual(Ip4Prefix{ .addr = addr4, .mask_bits = 3 }, Ip4Prefix.init(addr4, 3));
    try testing.expectEqual(Ip6Prefix{ .addr = addr6, .mask_bits = 3 }, Ip6Prefix.init(addr6, 3));

    try testing.expectEqual(u6, Ip4Prefix.MaskType);
    try testing.expectEqual(u8, Ip6Prefix.MaskType);
}

test "Prefix/parse4" {
    try testing.expectEqual(
        Ip4Prefix{ .addr = v4.Addr.fromArray(u8, [_]u8{ 192, 0, 2, 1 }), .mask_bits = 24 },
        try Ip4Prefix.parse("192.0.2.1/24"),
    );

    try testing.expectEqual(
        Ip4Prefix{ .addr = v4.Addr.fromArray(u8, [_]u8{ 192, 0, 2, 1 }), .mask_bits = 0 },
        try Ip4Prefix.parse("192.0.2.1/0"),
    );

    try testing.expectEqual(
        Ip4Prefix{ .addr = v4.Addr.fromArray(u8, [_]u8{ 192, 0, 2, 1 }), .mask_bits = 32 },
        try Ip4Prefix.parse("192.0.2.1/32"),
    );

    try testing.expectError(ParseError.NotEnoughOctets, Ip4Prefix.parse("192.0.2/24"));
    try testing.expectError(ParseError.NoBitMask, Ip4Prefix.parse("192.0.2/"));
    try testing.expectError(ParseError.NoBitMask, Ip4Prefix.parse("192.0.2"));
    try testing.expectError(ParseError.Overflow, Ip4Prefix.parse("192.0.2.1/33"));
    try testing.expectError(ParseError.InvalidCharacter, Ip4Prefix.parse("192.0.2.1/test"));
    try testing.expectError(ParseError.InvalidCharacter, Ip4Prefix.parse("192.0.2.1/-1"));
}

test "Prefix/parse6" {
    try testing.expectEqual(
        Ip6Prefix{ .addr = v6.Addr.fromArray(u16, [_]u16{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1 }), .mask_bits = 96 },
        try Ip6Prefix.parse("2001:db8::1/96"),
    );

    try testing.expectEqual(
        Ip6Prefix{ .addr = v6.Addr.fromArray(u16, [_]u16{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1 }), .mask_bits = 0 },
        try Ip6Prefix.parse("2001:db8::1/0"),
    );

    try testing.expectEqual(
        Ip6Prefix{ .addr = v6.Addr.fromArray(u16, [_]u16{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1 }), .mask_bits = 128 },
        try Ip6Prefix.parse("2001:db8::1/128"),
    );

    try testing.expectError(ParseError.NotEnoughSegments, Ip6Prefix.parse("2001:db8:1/24"));
    try testing.expectError(ParseError.NoBitMask, Ip6Prefix.parse("2001:db8::1/"));
    try testing.expectError(ParseError.NoBitMask, Ip6Prefix.parse("2001:db8::1"));
    try testing.expectError(ParseError.Overflow, Ip6Prefix.parse("2001:db8::1/129"));
    try testing.expectError(ParseError.InvalidCharacter, Ip6Prefix.parse("2001:db8::1/test"));
    try testing.expectError(ParseError.InvalidCharacter, Ip6Prefix.parse("2001:db8::1/-1"));
}
