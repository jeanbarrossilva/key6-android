// Copyright © Jean Silva
//
// This file is part of the Key6 open-source project.
//
// Key6 is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// Key6 is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses.

allocator: ?std.mem.Allocator,
result: ?std.process.RunResult,
backing_paths: std.ArrayList([]const u8),

const configuration = @import("configuration/root.zig");
const LineReadingState = union(enum) {
    line_start,
    line_bulk,
    line_end,
    file_end,
};
const PathFilter = @import("path_filter.zig").PathFilter;
const Self = @This();
const std = @import("std");

const empty = Self{
    .allocator = null,
    .result = null,
    .backing_paths = .empty,
};
const find_prefix_arguments = &.{ "find", "-L", "." };
const find_argument_per_extension_count = 3;
const find_argument_per_exclusion_count = 2;
const find_argument_exclusion_regex_prefix = ".";
const find_argument_exclusion_regex_suffix = ".*";
const git_status_arrow = "->";

pub fn deinit(self: *Self) void {
    if (self.allocator) |allocator| {
        if (self.result) |result|
            configuration.run_results.deinit(result, allocator);
        self.backing_paths.deinit(allocator);
    }
}

pub fn paths(self: Self) []const []const u8 {
    return self.backing_paths.items;
}

pub fn all(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.process.Child.Cwd,
    output_writer: ?*std.Io.Writer,
    filter: PathFilter,
    extensions: []const []const u8,
    exclusions: []const []const u8,
) !Self {
    return switch (filter) {
        .all => _: {
            var arguments = try std.ArrayList([]const u8).initCapacity(
                allocator,
                find_prefix_arguments.len +
                    (extensions.len * find_argument_per_extension_count) +
                    (exclusions.len * find_argument_per_exclusion_count),
            );
            defer arguments.deinit(allocator);
            try arguments.appendSlice(allocator, find_prefix_arguments);
            for (extensions) |extension| {
                const name = try std.mem.concat(allocator, u8, &.{
                    "*",
                    extension,
                });
                if (arguments.items.len >
                    find_argument_per_extension_count)
                    try arguments.append(allocator, "-o");
                try arguments.append(allocator, "-name");
                try arguments.append(allocator, name);
            }
            for (exclusions) |excluded_path| {
                const regex =
                    try std.mem.concat(allocator, u8, &.{
                        find_argument_exclusion_regex_prefix,
                        excluded_path,
                        find_argument_exclusion_regex_suffix,
                    });
                try arguments.append(allocator, "-not");
                try arguments.append(allocator, "-path");
                try arguments.append(allocator, regex);
            }
            defer {
                for (arguments.items) |argument|
                    if (argument[0] == '*' or
                        configuration.strings.isDelimited(
                            argument,
                            find_argument_exclusion_regex_prefix,
                            find_argument_exclusion_regex_suffix,
                        ))
                        allocator.free(argument);
            }
            const find = try std.process.run(allocator, io, .{
                .argv = arguments.items,
                .cwd = cwd,
            });
            errdefer configuration.run_results.deinit(find, allocator);
            try configuration.run_results.validate(find, allocator, io);
            const LineReader = struct {
                allocator: std.mem.Allocator,
                output_writer: ?*std.Io.Writer,
                exclusions: []const []const u8,
                backing_paths: *std.ArrayList([]const u8),

                fn read(_self: *@This(), path: []const u8) !void {
                    try _self.backing_paths.append(_self.allocator, path);
                    if (_self.output_writer) |writer| {
                        try writer.print("{s}\n", .{path});
                        try writer.flush();
                    }
                }
            };
            var backing_paths = std.ArrayList([]const u8).empty;
            var line_reader = LineReader{
                .allocator = allocator,
                .output_writer = output_writer,
                .exclusions = exclusions,
                .backing_paths = &backing_paths,
            };
            try readLines(
                LineReader,
                &line_reader,
                find.stdout,
                LineReader.read,
            );
            break :_ .{
                .allocator = allocator,
                .result = find,
                .backing_paths = backing_paths,
            };
        },
        .specific => |filter_paths| _: {
            var backing_paths =
                try std.ArrayList([]const u8).initCapacity(
                    allocator,
                    filter_paths.len,
                );
            filter_path_loop: for (filter_paths) |filter_path| {
                for (exclusions) |excluded_path|
                    if (std.mem.eql(u8, filter_path, excluded_path))
                        continue :filter_path_loop;
                try backing_paths.append(allocator, filter_path);
            }
            if (output_writer) |writer| {
                for (filter_paths) |path| {
                    try writer.print("{s}\n", .{path});
                    try writer.flush();
                }
            }
            break :_ .{
                .allocator = allocator,
                .result = null,
                .backing_paths = backing_paths,
            };
        },
    };
}

pub fn staged(
    allocator: std.mem.Allocator,
    io: std.Io,
    cwd: std.process.Child.Cwd,
    output_writer: ?*std.Io.Writer,
    filter: PathFilter,
    extensions: []const []const u8,
    exclusions: []const []const u8,
) !Self {
    const git_status = try std.process.run(allocator, io, .{
        .argv = &.{ "git", "status", "--porcelain" },
        .cwd = cwd,
    });
    errdefer configuration.run_results.deinit(git_status, allocator);
    try configuration.run_results.validate(git_status, allocator, io);
    if (git_status.stdout.len == 0) {
        configuration.run_results.deinit(git_status, allocator);
        return .empty;
    }
    var backing_paths = std.ArrayList([]const u8).empty;

    const LineReader = struct {
        allocator: std.mem.Allocator,
        output_writer: ?*std.Io.Writer,
        filter: PathFilter,
        extensions: []const []const u8,
        exclusions: []const []const u8,
        backing_paths: *std.ArrayList([]const u8),

        fn read(self: *@This(), line: []const u8) !void {
            // obviously, we'll only format files that *will* be
            // commited. them having been deleted (i.e., their name
            // being prefixed with a "D") means they'll just be ignored.
            if (line[0] == 'D')
                return;

            const first_whitespace_index: ?usize =
                std.mem.indexOfScalar(u8, line, ' ');

            // tricky. there are some prefixes before the paths provided by
            // 'git status --porcelain' apart from the "D" one covered
            // above.
            //
            // now, we'll also watch out for "M", that *may* represent a
            // file move, and, in such case, will contain two components
            // after it: the old path, an arrow "->", and the new path;
            // otherwise, it's just one path.
            var path_index: usize =
                if (first_whitespace_index) |i| single: {
                    const second_whitespace_index =
                        if (line[0] == 'M')
                            std.mem.indexOfScalar(u8, line[i + 1 ..], ' ')
                        else
                            null;
                    const offset =
                        if (second_whitespace_index) |j| moved: {
                            const arrow_start_index =
                                j + git_status_arrow.len + 1;
                            const arrow_end_index =
                                arrow_start_index + git_status_arrow.len;
                            break :moved if (std.mem.eql(
                                u8,
                                git_status_arrow,
                                line[arrow_start_index..arrow_end_index],
                            ))
                                arrow_end_index
                            else
                                i;
                        } else _: {
                            break :_ 1;
                        };
                    break :single i + offset;
                } else _: {
                    break :_ 0;
                };

            while (std.ascii.isWhitespace(line[path_index]))
                path_index += 1;
            const path = line[path_index..];
            for (self.exclusions) |excluded_path|
                if (std.mem.eql(u8, path, excluded_path))
                    return;

            // this O(n) loop is really, really unnecessary… instead, we
            // could use a std.StringHashMap rather than a std.ArrayList for
            // the backing path storage.
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

    var line_reader = LineReader{
        .allocator = allocator,
        .output_writer = output_writer,
        .filter = filter,
        .extensions = extensions,
        .exclusions = exclusions,
        .backing_paths = &backing_paths,
    };
    try readLines(
        LineReader,
        &line_reader,
        git_status.stdout,
        LineReader.read,
    );
    return .{
        .allocator = allocator,
        .result = git_status,
        .backing_paths = backing_paths,
    };
}

fn readLines(
    comptime Reader: anytype,
    reader: *Reader,
    text: []const u8,
    read: *const fn (*Reader, []const u8) anyerror!void,
) !void {
    var state = LineReadingState.line_start;
    var line_start_index: usize = 0;
    for (0..text.len) |index| {
        var line_end_index = index -| 1;
        switch (state) {
            .line_start => {
                state = .line_bulk;
                line_start_index = index;
                continue;
            },
            .line_bulk => {
                if (index == text.len - 2) {
                    state = .file_end;
                } else if (text[index] == '\n')
                    state = .line_end;
                continue;
            },
            .line_end => {
                state = .line_start;
            },
            .file_end => {
                line_end_index = index;
            },
        }
        try read(reader, text[line_start_index..line_end_index]);
    }
}
