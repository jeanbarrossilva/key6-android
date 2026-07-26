const std = @import("std");

pub const FileInclusion = enum {
    all,
    staged,

    pub fn pathsView(
        self: FileInclusion,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        output_writer: ?*std.Io.Writer,
        formatter: Formatter,
    ) !PathsView {
        return switch (self) {
            .all => .all(
                allocator,
                io,
                cwd,
                output_writer,
                formatter.extensions,
            ),
            .staged => .staged(
                allocator,
                io,
                cwd,
                output_writer,
                formatter.extensions,
            ),
        };
    }
};
const PathsView = struct {
    allocator: ?std.mem.Allocator,
    result: ?std.process.RunResult,
    backing_paths: std.ArrayList([]const u8),

    const LineScan = union(enum) {
        start,
        intermediate,
        end,
    };

    const empty = PathsView{
        .allocator = null,
        .result = null,
        .backing_paths = .empty,
    };
    const find_argv_prefix = &.{ "find", "." };

    pub fn deinit(self: *@This()) void {
        if (self.allocator) |allocator| {
            deinitResult(allocator, self.result.?);
            self.backing_paths.deinit(allocator);
        }
    }

    fn paths(self: PathsView) []const []const u8 {
        return self.backing_paths.items;
    }

    fn all(
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        output_writer: ?*std.Io.Writer,
        extensions: []const []const u8,
    ) !PathsView {
        var find_arguments = try std.ArrayList([]const u8).initCapacity(
            allocator,
            extensions.len * 3 + find_argv_prefix.len,
        );
        defer find_arguments.deinit(allocator);
        try find_arguments.appendSlice(allocator, find_argv_prefix);
        for (extensions) |extension| {
            const name = try std.mem.concat(allocator, u8, &.{
                "*",
                extension,
            });
            if (find_arguments.items.len > 3)
                try find_arguments.append(allocator, "-o");
            try find_arguments.append(allocator, "-name");
            try find_arguments.append(allocator, name);
        }
        defer {
            for (find_arguments.items) |argument|
                if (argument[0] == '*')
                    allocator.free(argument);
        }
        const find = try std.process.run(allocator, io, .{
            .argv = find_arguments.items,
            .cwd = cwd,
        });
        var backing_paths = std.ArrayList([]const u8).empty;

        const LineReadingContext = struct {
            allocator: std.mem.Allocator,
            output_writer: ?*std.Io.Writer,
            backing_paths: *std.ArrayList([]const u8),

            fn callback(_self: *@This(), path: []const u8) !void {
                try _self.backing_paths.append(_self.allocator, path);
                if (_self.output_writer) |writer| {
                    try writer.print("{s}\n", .{path});
                    try writer.flush();
                }
            }
        };

        var line_reading_context = LineReadingContext{
            .allocator = allocator,
            .output_writer = output_writer,
            .backing_paths = &backing_paths,
        };
        try readLines(
            LineReadingContext,
            &line_reading_context,
            find.stdout,
            LineReadingContext.callback,
        );
        return .{
            .allocator = allocator,
            .result = find,
            .backing_paths = backing_paths,
        };
    }

    fn staged(
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        output_writer: ?*std.Io.Writer,
        extensions: []const []const u8,
    ) !PathsView {
        const git_status = try std.process.run(allocator, io, .{
            .argv = &.{ "git", "status", "--porcelain" },
            .cwd = cwd,
        });
        if (git_status.stdout.len == 0) {
            deinitResult(allocator, git_status);
            return .empty;
        }
        var backing_paths = std.ArrayList([]const u8).empty;

        const LineReadingContext = struct {
            allocator: std.mem.Allocator,
            output_writer: ?*std.Io.Writer,
            extensions: []const []const u8,
            backing_paths: *std.ArrayList([]const u8),

            fn callback(self: *@This(), line: []const u8) !void {
                // obviously, we'll only format files that *will* be
                // commited. them having been deleted (i.e., their name
                // being prefixed with a "D") means they'll just be ignored.
                if (line[0] == 'D')
                    return;

                var path_index =
                    if (std.mem.indexOfScalar(u8, line, ' ')) |whitespace_index|
                        whitespace_index + 1
                    else
                        0;
                for (line[path_index..]) |character| {
                    if (std.ascii.isWhitespace(character)) {
                        path_index += 1;
                        continue;
                    }
                    break;
                }
                const path = line[path_index..];

                // this O(n) loop is really, really unnecessary… instead, we
                // could use a std.StringHashMap rather than an std.ArrayList
                // for the backing path storage.
                for (self.backing_paths.items) |previous_path|
                    if (path.len == previous_path.len and
                        std.mem.eql(u8, path, previous_path))
                        return;

                for (self.extensions, 0..) |extension, extension_index| {
                    if (std.mem.eql(
                        u8,
                        std.fs.path.extension(line),
                        extension,
                    ))
                        break;
                    if (extension_index == self.extensions.len - 1)
                        return;
                }
                try self.backing_paths.append(self.allocator, path);
                if (self.output_writer) |writer| {
                    try writer.print("{s}\n", .{path});
                    try writer.flush();
                }
            }
        };

        var line_reading_context = LineReadingContext{
            .allocator = allocator,
            .output_writer = output_writer,
            .extensions = extensions,
            .backing_paths = &backing_paths,
        };
        try readLines(
            LineReadingContext,
            &line_reading_context,
            git_status.stdout,
            LineReadingContext.callback,
        );
        return .{
            .allocator = allocator,
            .result = git_status,
            .backing_paths = backing_paths,
        };
    }

    fn readLines(
        comptime Context: anytype,
        context: *Context,
        text: []const u8,
        callback: *const fn (*Context, []const u8) anyerror!void,
    ) !void {
        var line_scan = LineScan.start;
        var line_start_index: usize = 0;
        for (0..text.len) |index| {
            switch (line_scan) {
                .start => {
                    line_scan = .intermediate;
                    line_start_index = index;
                    continue;
                },
                .intermediate => {
                    if (text[index] == '\n')
                        line_scan = .end;
                    continue;
                },
                .end => {
                    line_scan = .start;
                },
            }
            try callback(context, text[line_start_index .. index - 1]);
        }
    }
};
pub const Formatter = struct {
    identifier: []const u8,
    extensions: []const []const u8,
    arguments: []const []const u8,

    fn format(
        self: Formatter,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        paths: []const []const u8,
    ) !void {
        _ = paths;
        const arguments = try std.mem.concat(allocator, []const u8, &.{
            self.arguments,
        });
        defer allocator.free(arguments);
        const result = try std.process.run(allocator, io, .{
            .argv = arguments,
            .cwd = cwd,
        });
        deinitResult(allocator, result);
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.process.Child.Cwd,
    output_file_writer: *?std.Io.File.Writer,
    file_inclusion: FileInclusion,
    formatters: []const Formatter,
) !void {
    const output_writer = if (output_file_writer.*) |*file_writer|
        &file_writer.interface
    else
        null;
    for (formatters) |formatter| {
        var paths_view = try file_inclusion.pathsView(
            allocator,
            io,
            cwd,
            output_writer,
            formatter,
        );
        defer paths_view.deinit();
        try formatter.format(allocator, io, cwd, paths_view.paths());
    }
}

fn deinitResult(
    self: std.mem.Allocator,
    result: std.process.RunResult,
) void {
    self.free(result.stdout);
    self.free(result.stderr);
}
