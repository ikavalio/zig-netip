const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

pub fn AddrValue(comptime T: type) type {
    if (T != u128 and T != u32) {
        @compileError("unknown address type '" ++ @typeName(T) ++ "' (only u128 and u32 are supported)");
    }

    const type_size = @sizeOf(T);
    assert(type_size > 0 and (type_size & (type_size - 1) == 0));

    return packed struct {
        const Self = @This();
        pub const PositionType = math.Log2Int(T);
        pub const size = type_size;

        v: T,

        // create an address from the slice of integer values.
        // elements of the array are ordered in the network order.
        // each integer value has the network byte order.
        pub inline fn fromArrayNetOrder(comptime E: type, a: [size / @sizeOf(E)]E) Self {
            const p = @ptrCast(*align(@alignOf(u8)) const [size / @sizeOf(u8)]u8, &a);
            const v = mem.bigToNative(T, mem.bytesToValue(T, p));
            return Self{ .v = v };
        }

        // create an address from the slice of integer values.
        // elements of the array are ordered in the network order.
        // each integer value has the native byte order.
        pub inline fn fromArray(comptime E: type, a: [size / @sizeOf(E)]E) Self {
            var v: T = 0;

            inline for (a) |b, i| {
                v |= @as(T, b) << (@bitSizeOf(E) * ((size / @sizeOf(E)) - 1 - i));
            }

            return Self{ .v = v };
        }

        // convert the address to an array of integer values.
        // elements of the array are ordered in the network order.
        // each integer value has the native byte order.
        pub fn toArrayNetOrder(self: Self, comptime E: type) [size / @sizeOf(E)]E {
            var a = self.toArray(E);

            inline for (a) |b, i| {
                a[i] = mem.nativeToBig(E, b);
            }

            return a;
        }

        // convert the address to an array of integer values
        // array is ordered in the network order
        // components have native order
        pub inline fn toArray(self: Self, comptime E: type) [size / @sizeOf(E)]E {
            var a: [size / @sizeOf(E)]E = undefined;

            inline for (a) |_, i| {
                a[i] = self.get(E, i);
            }

            return a;
        }

        // convert the address to an array of integer values
        // array is ordered in the network order
        // components have native order
        pub inline fn get(self: Self, comptime E: type, i: PositionType) E {
            return @truncate(E, self.v >> (@bitSizeOf(E) * (size / @sizeOf(E) - 1 - i)));
        }
    };
}
