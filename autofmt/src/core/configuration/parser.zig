const Formatter = @import("Formatter.zig");
const Result = struct {
    allocator: ?std.mem.Allocator,
    backing_source: std.ArrayList(u8),
    json: std.json.Parsed([]Formatter),

    const empty = Result{
        .allocator = null,
        .backing_source = .empty,
        .json = .{
            .allocator = undefined,
            .value = &.{},
        },
    };

    pub fn formatters(self: Result) []const Formatter {
        return self.json.value;
    }

    pub fn deinit(self: *Result) void {
        const allocator = self.allocator orelse return;
        self.backing_source.deinit(allocator);
        self.json.deinit();
    }
};
const std = @import("std");

pub fn parseFile(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File) !Result {
    var source = std.ArrayList(u8).empty;
    var file_reader = file.reader(io, &.{});
    const reader = &file_reader.interface;
    try reader.appendRemaining(allocator, &source, .unlimited);
    return try parseSource(allocator, source);
}

fn parseSource(
    allocator: std.mem.Allocator,
    source: std.ArrayList(u8),
) !Result {
    return .{
        .allocator = allocator,
        .backing_source = source,
        .json = try std.json.parseFromSlice(
            []Formatter,
            allocator,
            source.items,
            .{},
        ),
    };
}

test parseSource {
    var result = try parseSource(std.testing.allocator,
        \\{
        \\  {
        \\    "identifier": "zig",
        \\    "arguments": ["zig", "fmt", "."],
        \\    "extensions": [".zig", ".zon"]
        \\ }
        \\}
    );
    defer result.deinit();
    std.testing.expectEquals(
        &.{
            .{
                .identifier = "zig",
                .arguments = &.{ "zig", "fmt", "." },
                .extensions = &.{ ".zig", ".zon" },
            },
        },
        result.formatters(),
    );
}
