const std = @import("std");
const math = std.math;
const sort = std.sort;
const testing = std.testing;

const prefix = @import("./prefix.zig");
const address = @import("./addr.zig");

// TODO: Aggregate adjacent intervals

// A variant of stdlib binary search that always returns the index
fn binarySearch(
    comptime T: type,
    key: T,
    items: []const T,
    context: anytype,
    comptime compareFn: fn (context: @TypeOf(context), lhs: T, rhs: T) math.Order,
) usize {
    var left: usize = 0;
    var right: usize = items.len;

    while (left < right) {
        const mid = left + (right - left) / 2;
        switch (compareFn(context, key, items[mid])) {
            .eq => return mid,
            .gt => left = mid + 1,
            .lt => right = mid,
        }
    }

    return left;
}

/// An PrefixSet type constructor representing an immutable search set of prefixes.
pub fn PrefixSetForType(comptime P: type) type {
    return struct {
        const Self = @This();

        els: []const P,

        fn comparator(c: void, l: P, r: P) math.Order {
            _ = c;
            return switch (l.addr.order(r.addr)) {
                .eq => math.order(r.mask_bits, l.mask_bits), // reverse
                else => |v| v,
            };
        }

        fn sorter(c: void, l: P, r: P) bool {
            return comparator(c, l, r) == math.Order.lt;
        }

        pub fn init(input: []P) Self {
            for (input) |el, i| {
                input[i] = el.canonical();
            }

            sort.sort(P, input, {}, sorter);

            return Self{ .els = input };
        }

        pub fn containsAddr(self: Self, needle: P.AddrType) bool {
            return self.containsPrefix(P.init(needle, P.maxMaskBits) catch unreachable);
        }

        inline fn contains(self: Self, needle: P, i: usize) bool {
            if (i < self.els.len) {
                const incl = self.els[i].testInclusion(needle);
                return incl == prefix.Inclusion.super or incl == prefix.Inclusion.eq;
            }

            return false;
        }

        pub fn containsPrefix(self: Self, needle: P) bool {
            if (self.els.len == 0) return false;

            // do a binary search on the prefixes canonical address
            const needle_canon = needle.canonical();
            const i = binarySearch(P, needle_canon, self.els, {}, comparator);

            return (self.contains(needle_canon, i)) or (i > 0 and self.contains(needle_canon, i - 1));
        }

        pub fn containedInPrefix(self: Self, needle: P) bool {
            _ = needle;
            _ = self;
            return false;
        }
    };
}

pub const Ip4PrefixSet = PrefixSetForType(prefix.Ip4Prefix);
pub const Ip6PrefixSet = PrefixSetForType(prefix.Ip6Prefix);

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

        const set = Ip4PrefixSet.init(&ps);
        try testing.expectEqualSlices(prefix.Ip4Prefix, &expected, set.els);
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

        const set = Ip6PrefixSet.init(&ps);
        try testing.expectEqualSlices(prefix.Ip6Prefix, &expected, set.els);
    }
}

test "Ip4PrefixSet/containsPrefix" {
    const test_prefix = try prefix.Ip4Prefix.parse("10.20.30.0/24");
    const test_address = try address.Ip4Addr.parse("10.20.30.40");
    const control_prefix = try prefix.Ip4Prefix.parse("1.2.3.0/24");
    const control_address = try address.Ip4Addr.parse("1.2.3.4");

    {
        const empty_set = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{});
        try testing.expect(!empty_set.containsPrefix(test_prefix));
        try testing.expect(!empty_set.containsAddr(test_address));
        try testing.expect(!empty_set.containsPrefix(control_prefix));
        try testing.expect(!empty_set.containsAddr(control_address));
    }

    {
        const trivial_set = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{test_prefix});        
        try testing.expect(trivial_set.containsPrefix(test_prefix));
        try testing.expect(trivial_set.containsAddr(test_address));
        try testing.expect(!trivial_set.containsPrefix(control_prefix));
        try testing.expect(!trivial_set.containsAddr(control_address));
    }

    {
        const trivial_addr_set = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.init(test_address, prefix.Ip4Prefix.maxMaskBits),
        });        
        try testing.expect(!trivial_addr_set.containsPrefix(test_prefix));
        try testing.expect(trivial_addr_set.containsAddr(test_address));
        try testing.expect(!trivial_addr_set.containsPrefix(control_prefix));
        try testing.expect(!trivial_addr_set.containsAddr(control_address));
    }

    {
        const unique_cover_sets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.parse("10.0.0.0/8"),
            try prefix.Ip4Prefix.parse("172.16.0.0/16"),
            try prefix.Ip4Prefix.parse("192.168.0.0/24"),
        });

        try testing.expect(unique_cover_sets.containsPrefix(test_prefix));
        try testing.expect(unique_cover_sets.containsAddr(test_address));
        try testing.expect(!unique_cover_sets.containsPrefix(control_prefix));
        try testing.expect(!unique_cover_sets.containsAddr(control_address));
    }

    {
        const nonunique_cover_sets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.parse("10.0.0.0/8"),
            try prefix.Ip4Prefix.parse("10.20.0.0/16"),
            try prefix.Ip4Prefix.parse("10.20.30.0/24"),
            try prefix.Ip4Prefix.parse("10.20.30.0/28"),
            try prefix.Ip4Prefix.parse("172.16.0.0/16"),
            try prefix.Ip4Prefix.parse("172.16.10.0/24"),
            try prefix.Ip4Prefix.parse("192.168.0.0/24"),
        });

        try testing.expect(nonunique_cover_sets.containsPrefix(test_prefix));
        try testing.expect(nonunique_cover_sets.containsAddr(test_address));
        try testing.expect(!nonunique_cover_sets.containsPrefix(control_prefix));
        try testing.expect(!nonunique_cover_sets.containsAddr(control_address));
    }

    {
        const nonunique_cover_sets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.parse("10.0.0.0/8"),
            try prefix.Ip4Prefix.parse("10.20.0.0/16"),
            try prefix.Ip4Prefix.parse("10.20.30.0/24"),
            try prefix.Ip4Prefix.parse("10.20.30.0/28"),
            try prefix.Ip4Prefix.parse("172.16.0.0/16"),
            try prefix.Ip4Prefix.parse("172.16.10.0/24"),
            try prefix.Ip4Prefix.parse("192.168.0.0/24"),
        });

        try testing.expect(nonunique_cover_sets.containsPrefix(test_prefix));
        try testing.expect(nonunique_cover_sets.containsAddr(test_address));
        try testing.expect(!nonunique_cover_sets.containsPrefix(control_prefix));
        try testing.expect(!nonunique_cover_sets.containsAddr(control_address));
    }

    {
        const nonunique_subsets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
            try prefix.Ip4Prefix.parse("10.20.30.0/32"),
            try prefix.Ip4Prefix.parse("10.20.30.0/28"),
            try prefix.Ip4Prefix.parse("10.20.30.0/25"),
            try prefix.Ip4Prefix.parse("10.20.30.128/25"),
            try prefix.Ip4Prefix.parse("172.16.0.0/16"),
            try prefix.Ip4Prefix.parse("172.16.10.0/24"),
            try prefix.Ip4Prefix.parse("192.168.0.0/24"),
        });

        try testing.expect(!nonunique_subsets.containsPrefix(test_prefix));
        try testing.expect(nonunique_subsets.containsAddr(test_address));
        try testing.expect(!nonunique_subsets.containsPrefix(control_prefix));
        try testing.expect(!nonunique_subsets.containsAddr(control_address));
    }
}
