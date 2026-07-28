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

const run_results = @import("run_results.zig");
const std = @import("std");

pub const Formatter = struct {
    identifier: []const u8,
    extensions: []const []const u8,
    arguments: []const []const u8,

    const Error = error{
        MalformedExtension,
        MissingArguments,
        MissingExtensions,
        Unidentified,
    };

    pub const zig = Formatter{
        .identifier = "zig",
        .extensions = &.{".zig"},
        .arguments = &.{ "zig", "fmt" },
    };

    pub fn validate(self: Formatter) Error!void {
        if (self.identifier.len == 0)
            return Error.Unidentified;
        if (self.extensions.len == 0)
            return Error.MissingExtensions;
        if (self.arguments.len == 0)
            return Error.MissingArguments;
    }

    pub fn format(
        self: Formatter,
        allocator: std.mem.Allocator,
        io: std.Io,
        cwd: std.process.Child.Cwd,
        paths: []const []const u8,
    ) !void {
        const arguments = try std.mem.concat(allocator, []const u8, &.{
            self.arguments,
            paths,
        });
        defer allocator.free(arguments);
        const result = try std.process.run(allocator, io, .{
            .argv = arguments,
            .cwd = cwd,
        });
        run_results.deinit(result, allocator);
    }
};

test "validate(): errors when unidentified" {
    errors: {
        try std.testing.expectError(
            Formatter.Error.Unidentified,
            Formatter.validate(.{
                .identifier = "",
                .extensions = Formatter.zig.extensions,
                .arguments = Formatter.zig.arguments,
            }),
        );
        break :errors;
    }
}

test "validate(): errors if extensions are missing" {
    try std.testing.expectError(
        Formatter.Error.MissingExtensions,
        Formatter.validate(.{
            .identifier = Formatter.zig.identifier,
            .extensions = &.{},
            .arguments = Formatter.zig.arguments,
        }),
    );
}

test "validate(): errors if arguments are missing" {
    try std.testing.expectError(
        Formatter.Error.MissingArguments,
        Formatter.validate(.{
            .identifier = Formatter.zig.identifier,
            .extensions = Formatter.zig.extensions,
            .arguments = &.{},
        }),
    );
}

test "validate(): succeeds if valid" {
    try Formatter.zig.validate();
}
