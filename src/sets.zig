const std = @import("std");
const math = std.math;
const sort = std.sort;
const testing = std.testing;

const prefix = @import("./prefix.zig");

/// An PrefixSet type constructor representing an immutable search set of prefixes.
pub fn PrefixSetForType(comptime P: type) type {
    return struct {
        const Self = @This();

        els: []const P,

        fn sortF(c: void, l: P, r: P) bool {
            _ = c;
            return switch (l.addr.order(r.addr)) {
                .eq => l.mask_bits > r.mask_bits,
                else => |v| v == math.Order.lt,
            };
        }

        pub fn init(input: []P) Self {
            for (input) |el, i| {
                input[i] = el.canonical();
            }

            sort.sort(P, input, {}, sortF);

            return Self{ .els = input };
        } 
    };
}

pub const Ip4PrefixSet = PrefixSetForType(prefix.Ip4Prefix);
pub const Ip6PrefixSet = PrefixSetForType(prefix.Ip6Prefix);
pub const PrefixSet = PrefixSetForType(prefix.Prefix);

test "PrefixSet/init" {
    {
        // ipv4
        var ps = [_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.parse("10.0.0.0/8"),
            try prefix.Ip4Prefix.parse("10.0.0.0/16"),
            try prefix.Ip4Prefix.parse("192.168.10.1/28"),
            try prefix.Ip4Prefix.parse("10.0.0.0/24"),
            try prefix.Ip4Prefix.parse("192.168.10.1/24"),
        };

        const expected = [_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.parse("10.0.0.0/24"),
            try prefix.Ip4Prefix.parse("10.0.0.0/16"),
            try prefix.Ip4Prefix.parse("10.0.0.0/8"),
            try prefix.Ip4Prefix.parse("192.168.10.0/28"),
            try prefix.Ip4Prefix.parse("192.168.10.0/24"),
        };

        const set = Ip4PrefixSet.init(ps[0..]);

        try testing.expectEqualSlices(prefix.Ip4Prefix, expected[0..], set.els);
    }

    {
        // ipv6
        var ps = [_]prefix.Ip6Prefix{
            try prefix.Ip6Prefix.parse("2001:db8::48:0:1/96"),
            try prefix.Ip6Prefix.parse("2001:db8::48:0:1/112"),
            try prefix.Ip6Prefix.parse("2001:db8::48:0:1/127"),
            try prefix.Ip6Prefix.parse("2001:db8::32:0:1/96"),
            try prefix.Ip6Prefix.parse("2001:db8::32:0:1/112"),
            try prefix.Ip6Prefix.parse("2001:db8::32:0:1/127"),
        };

        const expected = [_]prefix.Ip6Prefix{
            try prefix.Ip6Prefix.parse("2001:db8::32:0:0/127"),
            try prefix.Ip6Prefix.parse("2001:db8::32:0:0/112"),
            try prefix.Ip6Prefix.parse("2001:db8::32:0:0/96"),
            try prefix.Ip6Prefix.parse("2001:db8::48:0:0/127"),
            try prefix.Ip6Prefix.parse("2001:db8::48:0:0/112"),
            try prefix.Ip6Prefix.parse("2001:db8::48:0:0/96"),
        };

        const set = Ip6PrefixSet.init(ps[0..]);

        try testing.expectEqualSlices(prefix.Ip6Prefix, expected[0..], set.els);
    }
}
