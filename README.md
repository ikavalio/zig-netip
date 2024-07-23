# zig-netip

This is mostly an educational project to implement a library similar to go's [netip](https://pkg.go.dev/net/netip) 
using zig idioms and comptime features. 

The library targets the latest stable release which is currently `0.13`.

# Definitions

* `Ip4Addr`, `Ip6Addr`, `Ip6AddrScoped` (and an `Addr` union) address types that're small value types.
They can be converted to `std.net.Ip4Address` or 
`std.net.Ip6Address`. All types have a bunch of comptime 
friendly methods, e.g. `parse`, `get`, `toArray`, and 
flexible-ish `format` specifiers.
* `Ip4Prefix`, `Ip6Prefix` (and a `Prefix` union) address types that're built on top of 
`Ip4Addr` and `Ip6Addr` abstractions.

# Examples

Check [the netip tests](../main/src/netip.zig) for more.

```zig
test "Addr Example" {
    // ipv4 create
    const v4_addr1 = comptime try Ip4Addr.parse("192.0.2.1");
    const v4_addr2 = try Addr.parse("192.0.2.1");
    const v4_addr3 = Ip4Addr.fromArray(u8, [_]u8{ 192, 0, 2, 2 });
    const v4_addr4 = Ip4Addr.fromArray(u16, [_]u16{ 0xC000, 0x0202 });
    const v4_addr5 = Addr.init4(Ip4Addr.init(0xC0000203));
    const v4_addr6 = Ip4Addr.fromNetAddress(try std.net.Ip4Address.parse("192.0.2.3", 1));

    // ipv6 create
    const v6_addr1 = comptime try Ip6Addr.parse("2001:db8::1");
    const v6_addr2 = try Addr.parse("2001:db8::1");
    const v6_addr3 = Ip6Addr.fromArray(u8, [_]u8{ 0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 });
    const v6_addr4 = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2 });
    const v6_addr5 = Addr.init6(Ip6Addr.init(0x2001_0db8_0000_0000_0000_0000_0000_0003));
    const v6_addr6 = Ip6Addr.fromNetAddress(try std.net.Ip6Address.parse("2001:db8::3", 1));

    // ipv6 scoped
    const v6_scoped1 = comptime try Ip6AddrScoped.parse("2001:db8::1%eth2");
    const v6_scoped2 = try Addr.parse("2001:db8::2%4");

    // handle parsing errors
    try testing.expect(Ip4Addr.parse("-=_=-") == Ip4Addr.ParseError.InvalidCharacter);
    try testing.expect(Addr.parse("0.-=_=-") == Addr.ParseError.InvalidCharacter);
    try testing.expect(Ip6Addr.parse("-=_=-") == Ip6Addr.ParseError.InvalidCharacter);
    try testing.expect(Addr.parse("::-=_=-") == Addr.ParseError.InvalidCharacter);

    // copy
    const v4_addr7 = v4_addr5;
    const v6_addr8 = v6_addr3;

    _ = .{v4_addr7, v4_addr4, v4_addr6, v6_scoped1, v6_scoped2, v6_addr4, v6_addr6};

    // compare via values
    try testing.expectEqual(math.Order.eq, order(v4_addr1, v4_addr2.v4));
    try testing.expectEqual(math.Order.lt, order(v6_addr1, v6_addr8));
    try testing.expectEqual(math.Order.gt, order(v6_addr8, v6_addr1));
    try testing.expectEqual(math.Order.gt, order(v6_addr2, v4_addr2)); // cross AF comparison

    // print
    try testing.expectFmt("192.0.2.1", "{}", .{v4_addr1});
    try testing.expectFmt("c0.00.02.02", "{X}", .{v4_addr3});
    try testing.expectFmt("11000000.0.10.11", "{b}", .{v4_addr5});
    try testing.expectFmt("2001:db8::1", "{}", .{v6_addr1});
    try testing.expectFmt("2001:db8:0:0:0:0:0:2", "{xE}", .{v6_addr3});
    try testing.expectFmt("2001:0db8::0003", "{X}", .{v6_addr5});
    try testing.expectFmt("2001:0db8:0000:0000:0000:0000:0000:0001", "{XE}", .{v6_addr2});
}

test "Prefix Example" {
    // create a ipv6 prefix
    const v6_prefix1 = try Ip6Prefix.init(try Ip6Addr.parse("2001:db8:85a3::1"), 48);
    const v6_prefix2 = try Prefix.parse("2001:db8:85a3::/48");

    // create a prefix
    const v4_prefix1 = try Ip4Prefix.init(try Ip4Addr.parse("192.0.2.1"), 24);
    const v4_prefix2 = try Prefix.parse("192.0.2.1/24");

    // compare mask bits
    try testing.expectEqual(v6_prefix1.maskBits(), v6_prefix2.v6.maskBits());
    try testing.expectEqual(v4_prefix1.maskBits(), v4_prefix2.v4.maskBits());

    // handle parsing errors
    try testing.expectError(Prefix.ParseError.Overflow, Prefix.parse("2001:db8::/256"));
    try testing.expectError(Prefix.ParseError.Overflow, Prefix.parse("1.1.1.1/33"));

    // print
    try testing.expectFmt("2001:db8:85a3::1/48", "{}", .{v6_prefix1});
    try testing.expectFmt("2001:0db8:85a3::0001/48", "{X}", .{v6_prefix1});
    try testing.expectFmt("2001:db8:85a3::-2001:db8:85a3:ffff:ffff:ffff:ffff:ffff", "{R}", .{v6_prefix1});
    try testing.expectFmt("192.0.2.0/24", "{}", .{v4_prefix1.canonical()});
    try testing.expectFmt("192.0.2.0-192.0.2.255", "{R}", .{v4_prefix1});

    // contains address
    try testing.expect(v6_prefix2.containsAddr(try Addr.parse("2001:db8:85a3:cafe::efac")));
    try testing.expect(v4_prefix2.containsAddr(try Addr.parse("192.0.2.42")));

    // inclusion and overlap test
    try testing.expectEqual(PrefixInclusion.sub, v6_prefix1.testInclusion(try Ip6Prefix.parse("2001:db8::/32")));
    try testing.expect(v6_prefix2.overlaps(try Prefix.parse("2001:db8::/32")));
    try testing.expectEqual(PrefixInclusion.sub, v4_prefix1.testInclusion(try Ip4Prefix.parse("192.0.2.0/16")));
    try testing.expect(v4_prefix2.overlaps(try Prefix.parse("192.0.2.0/16")));
}
```
