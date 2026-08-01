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

const autofmt = @import("autofmt");
const clap = @import("clap");
const std = @import("std");

const parameters = clap.parseParamsComptime(
    \\-h, --help    Display information on how to use this program.
    \\-p, --print   Print the paths of files that have been formatted after formatting them.
    \\-s, --staged  Only formats files that will be included in the next Git commit.
    \\<PATH>
);

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const cwd_directory = std.Io.Dir.cwd();
    const cwd_path = try cwd_directory.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(cwd_path);
    const subprocess_cwd = std.process.Child.Cwd{ .path = cwd_path };
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
    const paths = @as([]const []const u8, @ptrCast(&input.positionals));
    var non_blank_paths = try filterNotBlank(allocator, paths);
    defer non_blank_paths.deinit(allocator);
    const path_filter: autofmt.PathFilter =
        if (non_blank_paths.items.len == 0)
            .all
        else
            .{ .specific = non_blank_paths.items };
    const configuration_file = try cwd_directory.openFile(io, ".autofmt.json", .{
        .allow_directory = false,
        .lock = .shared,
    });
    defer configuration_file.close(io);
    var configuration_parsing_result =
        try autofmt.configuration.parser.parseFile(
            allocator,
            io,
            configuration_file,
        );
    defer configuration_parsing_result.deinit();
    try autofmt.run(
        allocator,
        io,
        subprocess_cwd,
        &stdout_writer,
        file_inclusion,
        path_filter,
        configuration_parsing_result.formatters(),
    );
}

fn filterNotBlank(
    allocator: std.mem.Allocator,
    strings: []const []const u8,
) !std.ArrayList([]const u8) {
    if (strings.len == 0)
        return .empty;
    var non_blank =
        try std.ArrayList([]const u8).initCapacity(allocator, strings.len);
    for (strings) |string| {
        if (autofmt.configuration.strings.isBlank(string))
            continue;
        try non_blank.append(allocator, string);
    }
    return non_blank;
}
