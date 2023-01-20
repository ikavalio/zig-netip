pub fn invalidFmtErr(comptime fmt: []const u8, comptime value: type) void {
    @compileError("invalid format string '" ++ fmt ++ "' for type '" ++ @typeName(value) ++ "'");
}
