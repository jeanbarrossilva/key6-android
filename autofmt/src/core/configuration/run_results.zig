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

const Self = std.process.RunResult;
const std = @import("std");

pub fn validate(self: Self, allocator: std.mem.Allocator, io: std.Io) !void {
    if (self.stderr.len == 0)
        return;
    const stderr_buffer = try allocator.alloc(u8, self.stderr.len);
    defer allocator.free(stderr_buffer);
    var stderr_file_writer =
        std.Io.File.stderr().writer(io, stderr_buffer);
    const stderr_writer = &stderr_file_writer.interface;
    try stderr_writer.writeAll(self.stderr);
    try stderr_writer.flush();
    return error.ErroredSubprocess;
}

pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
    allocator.free(self.stdout);
    allocator.free(self.stderr);
}
