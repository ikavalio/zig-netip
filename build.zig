const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("zig-netip", "src/netip.zig");
    lib.setBuildMode(mode);
    lib.install();

    const example_test = b.addTest("src/netip.zig");
    example_test.setBuildMode(mode);

    const ip4addr_test = b.addTest("src/ip4addr.zig");
    ip4addr_test.setBuildMode(mode);

    const ip6addr_test = b.addTest("src/ip6addr.zig");
    ip6addr_test.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&ip4addr_test.step);
    test_step.dependOn(&ip6addr_test.step);
    test_step.dependOn(&example_test.step);
}
