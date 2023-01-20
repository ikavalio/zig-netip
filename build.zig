const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("zig-netip", "src/netip.zig");
    lib.setBuildMode(mode);
    lib.install();

    const example_test = b.addTest("src/netip.zig");
    example_test.setBuildMode(mode);

    const addr_test = b.addTest("src/addr.zig");
    addr_test.setBuildMode(mode);

    const prefix_test = b.addTest("src/prefix.zig");
    prefix_test.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&addr_test.step);
    test_step.dependOn(&example_test.step);
    test_step.dependOn(&prefix_test.step);
}
