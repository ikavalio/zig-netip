# zig-netip

This is mostly an educational project to implement a library similar to go's [netip](https://pkg.go.dev/net/netip) 
using zig idioms and comptime features. 

Package defines:

* `Ip4Addr`, `I6Addr` address types that're small value types.
They can be converted to `std.net.Ip4Address` or 
`std.net.Ip6Address`. Both types have a bunch of comptime 
friendly methods, e.g. `parse`, `get`, `toArray`, and 
flexible-ish `format` specifiers.
