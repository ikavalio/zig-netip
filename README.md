# zig-netip

This is mostly an educational project to implement a library similar to go's [netip](https://pkg.go.dev/net/netip) 
using zig idioms and comptime features. 

# Definitions

* `Ip4Addr`, `Ip6Addr` address types that're small value types.
They can be converted to `std.net.Ip4Address` or 
`std.net.Ip6Address`. Both types have a bunch of comptime 
friendly methods, e.g. `parse`, `get`, `toArray`, and 
flexible-ish `format` specifiers.
* `Ip4Prefix`, `Ip6Prefix` address types that're built on top of 
`Ip4Addr` and `Ip6Addr` abstractions.

# Examples

Check [the netip tests](../main/src/netip.zig) for more.

```zig
test "Ip6Addr Example" {
    // create
    const addr1 = comptime try Ip6Addr.parse("2001:db8::1");
    const addr2 = try Addr.parse("2001:db8::1");
    const addr3 = Ip6Addr.fromArray(u8, [_]u8{ 0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 });
    const addr4 = Ip6Addr.fromArray(u16, [_]u16{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2 });
    const addr5 = Ip6Addr.init(0x2001_0db8_0000_0000_0000_0000_0000_0003);
    const addr6 = Ip6Addr.fromNetAddress(try std.net.Ip6Address.parse("2001:db8::3", 1));

    // handle parsing errors
    try testing.expect(Ip6Addr.parse("-=_=-") == Ip6Addr.ParseError.InvalidCharacter);
    try testing.expect(Addr.parse("::-=_=-") == Addr.ParseError.InvalidCharacter);

    // copy
    const addr7 = addr5;
    const addr8 = addr3;

    // compare via values
    try testing.expectEqual(math.Order.eq, order(addr1, addr2.v6));
    try testing.expectEqual(math.Order.lt, order(addr1, addr8));
    try testing.expectEqual(math.Order.gt, order(addr7, addr1));
    try testing.expect(addr3.value() == addr4.value());
    try testing.expect(addr4.value() != addr6.value());
    try testing.expect(addr5.value() > addr4.value());

    // print
    try testing.expectFmt("2001:db8::1", "{}", .{addr1});
    try testing.expectFmt("2001:db8:0:0:0:0:0:2", "{xE}", .{addr3});
    try testing.expectFmt("2001:0db8::0003", "{X}", .{addr5});
    try testing.expectFmt("2001:0db8:0000:0000:0000:0000:0000:0001", "{XE}", .{addr2});
}

test "Ip6Prefix Example" {
    // create a prefix
    const prefix1 = try Ip6Prefix.init(try Ip6Addr.parse("2001:db8:85a3::1"), 48);
    const prefix2 = try Prefix.parse("2001:db8:85a3::/48");

    // compare mask bits
    try testing.expectEqual(prefix1.maskBits(), prefix2.v6.maskBits());

    // handle parsing errors
    try testing.expectError(Prefix.ParseError.Overflow, Prefix.parse("2001:db8::/256"));

    // print
    try testing.expectFmt("2001:db8:85a3::1/48", "{}", .{prefix1});
    try testing.expectFmt("2001:0db8:85a3::0001/48", "{X}", .{prefix1});
    try testing.expectFmt("2001:db8:85a3::-2001:db8:85a3:ffff:ffff:ffff:ffff:ffff", "{R}", .{prefix1});

    // contains address
    try testing.expect(prefix1.containsAddr(try Ip6Addr.parse("2001:db8:85a3:cafe::efac")));

    // inclusion and overlap test
    try testing.expectEqual(PrefixInclusion.sub, prefix1.testInclusion(try Ip6Prefix.parse("2001:db8::/32")));
    try testing.expect(prefix2.overlaps(try Prefix.parse("2001:db8::/32")));
}
```
