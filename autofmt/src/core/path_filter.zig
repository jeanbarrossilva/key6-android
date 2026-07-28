pub const PathFilter = union(enum) {
    all,
    specific: []const []const u8,
};
