const autofmt = @import("autofmt");
const clap = @import("clap");
const std = @import("std");

const parameters = clap.parseParamsComptime(
    \\-h, --help    Display information on how to use this program.
    \\-p, --print   Print the paths of files that have been formatted after formatting them.
    \\-s, --staged  Only formats files that will be included in the next Git commit.
    \\<PATH>
);
const formatters = [_]autofmt.Formatter{
    .{
        .identifier = "kt",
        .extensions = &.{ ".kt", ".kts" },
        .arguments = &.{ "ktlint", "--format" },
    },
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const cwd_path = try std.Io.Dir.cwd().realPathFileAlloc(io, ".", allocator);
    defer allocator.free(cwd_path);
    const cwd = std.process.Child.Cwd{ .path = cwd_path };
    const parser = comptime .{ .PATH = clap.parsers.string };
    var diagnostic = clap.Diagnostic{};
    const input =
        clap.parse(clap.Help, &parameters, parser, init.minimal.args, .{
            .allocator = allocator,
            .diagnostic = &diagnostic,
        }) catch |err| {
            try diagnostic.reportToFile(io, .stderr(), err);
            return err;
        };
    defer input.deinit();
    if (input.args.help != 0)
        return clap.helpToFile(io, .stdout(), clap.Help, &parameters, .{});
    const file_inclusion: autofmt.FileInclusion =
        if (input.args.staged == 0) .all else .staged;
    var stdout_writer = if (input.args.print == 0)
        null
    else _: {
        var buffer: [4096]u8 = undefined;
        break :_ std.Io.File.stdout().writer(io, &buffer);
    };
    const sliced_positionals =
        @as([]const []const u8, @ptrCast(&input.positionals));
    var paths = try std.ArrayList([]const u8).initCapacity(
        allocator,
        sliced_positionals.len,
    );
    defer paths.deinit(allocator);
    var path_index = paths.items.len -| 1;
    while (paths.items.len > 0 and path_index >= 0) : (path_index -= 1) {
        const path = paths.items[path_index];
        for (path, 0..) |character, character_index| {
            if (character_index == path.len - 1) {
                _ = paths.swapRemove(path_index);
                break;
            }
            if (!std.ascii.isWhitespace(character))
                break;
        }
    }
    const path_filter: autofmt.PathFilter =
        if (paths.items.len == 0) .all else .{ .specific = paths.items };
    try autofmt.run(
        allocator,
        io,
        cwd,
        &stdout_writer,
        file_inclusion,
        path_filter,
        &formatters,
    );
}
