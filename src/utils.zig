
pub fn invalidFmtErr(comptime fmt: []const u8, value: type) void {
    @compileError("invalid format string '" ++ fmt ++ "' for type '" ++ @typeName(value) ++ "'");
}
