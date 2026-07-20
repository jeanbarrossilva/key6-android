const std = @import("std");

pub const StagedPathsView = struct {
    result: ?std.process.RunResult,
    paths: []const []const u8,

    const LineScan = union(enum) {
        start,
        intermediate,
        end,
    };

    const empty = StagedPathsView{
        .result = null,
        .paths = &.{},
    };

    pub fn deinit(self: StagedPathsView, allocator: std.mem.Allocator) void {
        if (self.result) |result| {
            free(allocator, result);
            allocator.free(self.paths);
        }
    }

    pub fn spawn(
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
    ) std.process.RunError!StagedPathsView {
        var git_status = try std.process.run(allocator, io, .{
            .argv = &.{ "git", "status", "--porcelain" },
            .cwd = cwd,
        });
        const is_empty =
            git_status.stdout.len == 1 and git_status.stdout[0] == '\n';
        if (is_empty) {
            free(allocator, git_status);
            return .empty;
        }
        var paths = std.ArrayList([]const u8).empty;
        var line_scan = LineScan.start;
        var line_start_index: usize = 0;
        errdefer paths.deinit(allocator);
        for (1..git_status.stdout.len - 1) |character_index| {
            const character = git_status.stdout[character_index];
            switch (line_scan) {
                .start => {
                    line_scan = .intermediate;
                    line_start_index = character_index;
                    continue;
                },
                .intermediate => {
                    if (character == '\n')
                        line_scan = .end;
                    continue;
                },
                .end => {
                    line_scan = .start;
                },
            }
            const line =
                git_status.stdout[line_start_index .. character_index - 1];

            // obviously, we'll only format files that *will* be commited. them
            // having been deleted (i.e., their name being prefixed with a "D")
            // means they'll just be ignored.
            if (line[0] == 'D')
                continue;

            const path_index =
                if (std.mem.findScalar(u8, line, ' ')) |whitespace_index| _: {
                    break :_ whitespace_index + 1;
                } else _: {
                    break :_ 0;
                };
            try paths.append(allocator, line[path_index..]);
        }
        return .{
            .result = git_status,
            .paths = try paths.toOwnedSlice(allocator),
        };
    }

    fn free(allocator: std.mem.Allocator, result: std.process.RunResult) void {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }
};
