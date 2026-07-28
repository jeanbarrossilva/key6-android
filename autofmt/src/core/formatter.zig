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

identifier: []const u8,
extensions: []const []const u8,
arguments: []const []const u8,

pub const zig = Self{
    .identifier = "zig",
    .extensions = &.{".zig", ".zig.zon"},
    .arguments = &.{"zig", "fmt"},
};

const Error = error{
    MalformedExtension,
    MissingArguments,
    MissingExtensions,
    Unidentified,
};
const Self = @This();
const run_results = @import("run_results.zig");
const std = @import("std");

pub fn validate(self: Self) Error!void {
    if (self.identifier.len == 0)
        return Error.Unidentified;
    if (self.extensions.len == 0)
        return Error.MissingExtensions;
    for (self.extensions) |extension| {
        if (extension.len <= 1 or extension[0] != '.')
            return Error.MalformedExtension;
        for (extension[1..]) |character|
            if (!std.ascii.isAlphanumeric(character))
                return Error.MalformedExtension;
    }
    if (self.arguments.len == 0)
        return Error.MissingArguments;
}

pub fn format(
    self: Self,
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

test "validate(): errors if unidentified" {
    try std.testing.expectError(
        Self.Error.Unidentified,
        Self.validate(.{
            .identifier = "",
            .extensions = Self.zig.extensions,
            .arguments = Self.zig.arguments,
        }),
    );
}

test "validate(): errors if extensions are missing" {
    try std.testing.expectError(
        Self.Error.MissingExtensions,
        Self.validate(.{
            .identifier = Self.zig.identifier,
            .extensions = &.{},
            .arguments = Self.zig.arguments,
        }),
    );
}

test "validate(): errors if extension is malformed" {
    const extensions = &.{"", "z", "zig", "zig zon"};
    for (extensions) |extension|
        try std.testing.expectError(
            Self.Error.MalformedExtensions,
            Self.validate(.{
                .identifier = Self.zig.identifier,
                .extensions = &.{extension},
                .arguments = Self.zig.arguments,
            }),
        );
}

test "validate(): errors if arguments are missing" {
    try std.testing.expectError(
        Self.Error.MissingArguments,
        Self.validate(.{
            .identifier = Self.zig.identifier,
            .extensions = Self.zig.extensions,
            .arguments = &.{},
        }),
    );
}

test "validate(): succeeds if valid" {
    try Self.zig.validate();
}
