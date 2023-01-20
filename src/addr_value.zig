const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

/// A generic type representing the IP address as a native-order integer.
/// The type is a bit useless by itself, and should be wrapped into
/// something more high level.
pub fn AddrValue(comptime T: type) type {
    if (T != u128 and T != u32) {
        @compileError("unknown address type '" ++ @typeName(T) ++ "' (only u128 and u32 are supported)");
    }

    const type_size = @sizeOf(T);
    assert(type_size > 0 and (type_size & (type_size - 1) == 0));

    return packed struct {
        const Self = @This();

        /// The internal type of the address.
        pub const InternalType = T;
        /// The integer type that can be used in shl/shr instructions
        /// The type can store any bit index of the parent type.
        pub const PositionType = math.Log2Int(T);
        /// the byte size of the parent type.
        pub const size = type_size;

        /// Raw native-order integer value that encodes the type.
        v: T,

        /// Wrap a native-order integer value into AddrValue.
        pub inline fn init(v: T) Self {
            return Self{ .v = v };
        }

        /// Create an AddrValue from the array of arbitrary integer values.
        /// Elements of the array are ordered in the network order (most-significant first).
        /// Each integer value has the network byte order.
        pub inline fn fromArrayNetOrder(comptime E: type, a: [size / @sizeOf(E)]E) Self {
            const p = @ptrCast(*align(@alignOf(u8)) const [size / @sizeOf(u8)]u8, &a);
            const v = mem.bigToNative(T, mem.bytesToValue(T, p));
            return Self{ .v = v };
        }

        /// Create an AddrValue from the array of arbitrary integer values.
        /// Elements of the array are ordered in the network order (most-significant first).
        /// Each integer value has the native byte order.
        pub inline fn fromArray(comptime E: type, a: [size / @sizeOf(E)]E) Self {
            var v: T = 0;

            inline for (a) |b, i| {
                v |= @as(T, b) << (@bitSizeOf(E) * ((size / @sizeOf(E)) - 1 - i));
            }

            return Self{ .v = v };
        }

        /// Convert the AddrValue to an array of generic integer values.
        /// Elements of the array are ordered in the network order (most-significant first).
        /// Each integer value has the network byte order.
        pub fn toArrayNetOrder(self: Self, comptime E: type) [size / @sizeOf(E)]E {
            var a = self.toArray(E);

            inline for (a) |b, i| {
                a[i] = mem.nativeToBig(E, b);
            }

            return a;
        }

        /// Convert the address to an array of generic integer values.
        /// Elemenets of the array is ordered in the network order (most-significant first).
        /// Each integer value has the native byte order.
        pub inline fn toArray(self: Self, comptime E: type) [size / @sizeOf(E)]E {
            var a: [size / @sizeOf(E)]E = undefined;

            inline for (a) |_, i| {
                a[i] = self.get(E, i);
            }

            return a;
        }

        /// Get an arbitrary integer value from the address.
        /// The value always has the native byte order.
        pub inline fn get(self: Self, comptime E: type, i: PositionType) E {
            return @truncate(E, self.v >> (@bitSizeOf(E) * (size / @sizeOf(E) - 1 - i)));
        }
    };
}
