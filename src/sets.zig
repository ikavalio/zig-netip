const std = @import("std");
const math = std.math;
const mem = std.mem;
const sort = std.sort;
const testing = std.testing;
const assert = std.debug.assert;

const prefix = @import("./prefix.zig");
const address = @import("./addr.zig");

// TODO: Aggregate adjacent intervals

fn TrieNode(comptime P: type) type {
    return struct {
        const Self = @This();
        const A = P.AddrType;
        const V = A.ValueType;
        const M = P.MaskBitsType;

        prefix: V,
        branches: [2]*Self,
        mask_min: ?M,
        // it takes less memory to store prefix indices than an actual mask
        // 2 x u8 for ipv6 vs. 1 x u128
        // 2 x u6 for ipv4 vs. 1 x u32
        start: M,
        end: M,

        inline fn is_leaf(self: *const Self) bool {
            return self.end == P.maxMaskBits;
        }

        inline fn branch_bit(self: *const Self) u1 {
            assert(!self.is_leaf());
            return @truncate(u1, math.shr(V, self.prefix, P.maxMaskBits - self.end - 1) & 1);
        }

        inline fn next_node(self: *const Self) *Self {
            assert(!self.is_leaf());
            return self.branches[self.branch_bit()];
        }

        inline fn prefix_mask(self: *Self) V {
            return ~(~0 << (self.end - self.start + 1)) << (P.maxMaskBits - self.end - 1);
        }

        inline fn compare(self: *Self, addr: A) V {
            return (addr.v & self.prefix_mask()) ^ self.prefix;
        }

        fn create_node(allocator: mem.Allocator, addr: A, s: M, e: M, branches: [2]*Self) !*Self {
            var node = try allocator.create(Self);
            node.start = s;
            node.end = e;
            node.prefix = addr & node.curr_prefix_mask();
            node.branches = branches;
            return node;
        }

        // TODO: aggregate adjacent prefixes
        fn append(self: *Self, allocator: mem.Allocator, c: P) !void {
            const cmp = self.compare(c.addr);
            if (cmp != 0) {
                const eq_prefix = @clz(cmp);
                const subnet = eq_prefix + 2;

                const next = self.branch_bit();
                var branches: [2]*Self = undefined;

                branches[next] = try create_node(allocator, self.prefix, subnet, self.end, self.branches);
                branches[~next] = try create_node(allocator, c.addr, subnet, P.maxMaskBits, undefined);

                // fix the mask stats on the remainder of the self
                if (self.mask_min) |mask| {
                    // transfer the mask if it belongs to the new node
                    if (mask >= subnet and mask <= self.end) {
                        branches[next].mask_min = mask;
                        self.mask_min = null;
                    }
                }

                self.end = eq_prefix + 1;
                self.prefix = self.prefix & self.curr_prefix_mask();
                self.branches = branches;

                // join the cmp == 0 path to recalculate the stats
                // along the new path
            }

            if (c.mask_bits >= self.start and c.mask_bits <= self.end) {
                self.mask_min = math.min(self.mask_min orelse c.mask_bits, c.mask_bits);
            } else if (c.mask_bits > self.end) {
                assert(!self.is_leaf());
                try self.next_node(c.addr).append(allocator, c);

                // if both branches are adjacent /N subnets, assume we have
                // a full /N-1 subnet
                const sl = self.branches[0].mask_min orelse P.maxMaskBits;
                const sr = self.branches[1].mask_min orelse P.maxMaskBits;
                if (sl == self.end and sr == self.end) {
                    self.mask_min = math.min(self.mask_min orelse (sl - 1), sl - 1);
                }
            }
        }

        // TODO: support mode contains vs. contained
        fn search(self: *Self, needle: P) bool {
            _ = self;
            _ = needle;
            return false;
        }

        fn destroy(self: *Self, allocator: mem.Allocator) !void {
            if (self.is_leaf()) return;

            for (self.branches) |bp| {
                try bp.destroy(allocator);
                try allocator.destroy(bp);
            }
        }
    };
}

const Ip4Trie = TrieNode(prefix.Ip4Prefix);
const Ip6Trie = TrieNode(prefix.Ip6Prefix);

test "Trie/primitives" {
    var node1 = Ip4Trie{ .prefix = 0b00000000_10101010_01010101_00000000, .start = 8, .end = 23, .mask_min = null, .branches = undefined };
    var node2 = Ip4Trie{ .prefix = 0b11110000_10101010_01010101_00001111, .start = 0, .end = 32, .mask_min = null, .branches = undefined };
    var node3 = Ip4Trie{ .prefix = 0b11110000_10101010_01010101_00001111, .start = 0, .end = 31, .mask_min = null, .branches = undefined };
    var node4 = Ip4Trie{ .prefix = 0b11110000_10101010_01010101_00001111, .start = 1, .end = 32, .mask_min = null, .branches = undefined };
    var node5 = Ip4Trie{ .prefix = 0b11110000_10101010_01010101_00001111, .start = 10, .end = 10, .mask_min = null, .branches = [_]*Ip4Trie{ &node1, &node2 } };

    const pn1 = &node1;
    const pn2 = &node2;
    const pn3 = &node3;
    const pn4 = &node4;
    const pn5 = &node5;

    try testing.expect(!pn1.is_leaf());
    try testing.expect(pn2.is_leaf());
    try testing.expect(!pn3.is_leaf());
    try testing.expect(pn4.is_leaf());
    try testing.expect(!pn5.is_leaf());

    try testing.expectEqual(@as(u1, 1), pn1.branch_bit());
    try testing.expectEqual(@as(u1, 1), pn3.branch_bit());
    try testing.expectEqual(@as(u1, 1), pn5.branch_bit());

    try testing.expectEqual(&node2, pn5.next_node());
}

// test "PrefixSet/init" {
//     {
//         // ipv4
//         var ps = [_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.parse("10.0.0.0/8"),
//             try prefix.Ip4Prefix.parse("10.0.0.0/16"),
//             try prefix.Ip4Prefix.parse("192.168.10.1/28"),
//             try prefix.Ip4Prefix.parse("10.0.0.0/24"),
//             try prefix.Ip4Prefix.parse("192.168.10.1/24"),
//         };

//         const expected = [_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.parse("10.0.0.0/24"),
//             try prefix.Ip4Prefix.parse("10.0.0.0/16"),
//             try prefix.Ip4Prefix.parse("10.0.0.0/8"),
//             try prefix.Ip4Prefix.parse("192.168.10.0/28"),
//             try prefix.Ip4Prefix.parse("192.168.10.0/24"),
//         };

//         const set = Ip4PrefixSet.init(&ps);
//         try testing.expectEqualSlices(prefix.Ip4Prefix, &expected, set.els);
//     }

//     {
//         // ipv6
//         var ps = [_]prefix.Ip6Prefix{
//             try prefix.Ip6Prefix.parse("2001:db8::48:0:1/96"),
//             try prefix.Ip6Prefix.parse("2001:db8::48:0:1/112"),
//             try prefix.Ip6Prefix.parse("2001:db8::48:0:1/127"),
//             try prefix.Ip6Prefix.parse("2001:db8::32:0:1/96"),
//             try prefix.Ip6Prefix.parse("2001:db8::32:0:1/112"),
//             try prefix.Ip6Prefix.parse("2001:db8::32:0:1/127"),
//         };

//         const expected = [_]prefix.Ip6Prefix{
//             try prefix.Ip6Prefix.parse("2001:db8::32:0:0/127"),
//             try prefix.Ip6Prefix.parse("2001:db8::32:0:0/112"),
//             try prefix.Ip6Prefix.parse("2001:db8::32:0:0/96"),
//             try prefix.Ip6Prefix.parse("2001:db8::48:0:0/127"),
//             try prefix.Ip6Prefix.parse("2001:db8::48:0:0/112"),
//             try prefix.Ip6Prefix.parse("2001:db8::48:0:0/96"),
//         };

//         const set = Ip6PrefixSet.init(&ps);
//         try testing.expectEqualSlices(prefix.Ip6Prefix, &expected, set.els);
//     }
// }

// test "Ip4PrefixSet/containsPrefix" {
//     const test_prefix = try prefix.Ip4Prefix.parse("10.20.30.0/24");
//     const test_address = try address.Ip4Addr.parse("10.20.30.40");
//     const control_prefix = try prefix.Ip4Prefix.parse("1.2.3.0/24");
//     const control_address = try address.Ip4Addr.parse("1.2.3.4");

//     {
//         const empty_set = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{});
//         try testing.expect(!empty_set.containsPrefix(test_prefix));
//         try testing.expect(!empty_set.containsAddr(test_address));
//         try testing.expect(!empty_set.containsPrefix(control_prefix));
//         try testing.expect(!empty_set.containsAddr(control_address));
//     }

//     {
//         const trivial_set = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{test_prefix});
//         try testing.expect(trivial_set.containsPrefix(test_prefix));
//         try testing.expect(trivial_set.containsAddr(test_address));
//         try testing.expect(!trivial_set.containsPrefix(control_prefix));
//         try testing.expect(!trivial_set.containsAddr(control_address));
//     }

//     {
//         const trivial_addr_set = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.init(test_address, prefix.Ip4Prefix.maxMaskBits),
//         });
//         try testing.expect(!trivial_addr_set.containsPrefix(test_prefix));
//         try testing.expect(trivial_addr_set.containsAddr(test_address));
//         try testing.expect(!trivial_addr_set.containsPrefix(control_prefix));
//         try testing.expect(!trivial_addr_set.containsAddr(control_address));
//     }

//     {
//         const unique_cover_sets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.parse("10.0.0.0/8"),
//             try prefix.Ip4Prefix.parse("172.16.0.0/16"),
//             try prefix.Ip4Prefix.parse("192.168.0.0/24"),
//         });

//         try testing.expect(unique_cover_sets.containsPrefix(test_prefix));
//         try testing.expect(unique_cover_sets.containsAddr(test_address));
//         try testing.expect(!unique_cover_sets.containsPrefix(control_prefix));
//         try testing.expect(!unique_cover_sets.containsAddr(control_address));
//     }

//     {
//         const nonunique_cover_sets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.parse("10.0.0.0/8"),
//             try prefix.Ip4Prefix.parse("10.20.0.0/16"),
//             try prefix.Ip4Prefix.parse("10.20.30.0/24"),
//             try prefix.Ip4Prefix.parse("10.20.30.0/28"),
//             try prefix.Ip4Prefix.parse("172.16.0.0/16"),
//             try prefix.Ip4Prefix.parse("172.16.10.0/24"),
//             try prefix.Ip4Prefix.parse("192.168.0.0/24"),
//         });

//         try testing.expect(nonunique_cover_sets.containsPrefix(test_prefix));
//         try testing.expect(nonunique_cover_sets.containsAddr(test_address));
//         try testing.expect(!nonunique_cover_sets.containsPrefix(control_prefix));
//         try testing.expect(!nonunique_cover_sets.containsAddr(control_address));
//     }

//     {
//         const nonunique_cover_sets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.parse("10.0.0.0/8"),
//             try prefix.Ip4Prefix.parse("10.20.0.0/16"),
//             try prefix.Ip4Prefix.parse("10.20.30.0/24"),
//             try prefix.Ip4Prefix.parse("10.20.30.0/28"),
//             try prefix.Ip4Prefix.parse("172.16.0.0/16"),
//             try prefix.Ip4Prefix.parse("172.16.10.0/24"),
//             try prefix.Ip4Prefix.parse("192.168.0.0/24"),
//         });

//         try testing.expect(nonunique_cover_sets.containsPrefix(test_prefix));
//         try testing.expect(nonunique_cover_sets.containsAddr(test_address));
//         try testing.expect(!nonunique_cover_sets.containsPrefix(control_prefix));
//         try testing.expect(!nonunique_cover_sets.containsAddr(control_address));
//     }

//     {
//         const nonunique_subsets = Ip4PrefixSet.init(&[_]prefix.Ip4Prefix{
//             try prefix.Ip4Prefix.parse("10.20.30.0/32"),
//             try prefix.Ip4Prefix.parse("10.20.30.0/28"),
//             try prefix.Ip4Prefix.parse("10.20.30.0/25"),
//             try prefix.Ip4Prefix.parse("10.20.30.128/25"),
//             try prefix.Ip4Prefix.parse("172.16.0.0/16"),
//             try prefix.Ip4Prefix.parse("172.16.10.0/24"),
//             try prefix.Ip4Prefix.parse("192.168.0.0/24"),
//         });

//         try testing.expect(!nonunique_subsets.containsPrefix(test_prefix));
//         try testing.expect(nonunique_subsets.containsAddr(test_address));
//         try testing.expect(!nonunique_subsets.containsPrefix(control_prefix));
//         try testing.expect(!nonunique_subsets.containsAddr(control_address));
//     }
// }
