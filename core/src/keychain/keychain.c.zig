// Copyright © Jean Silva
//
// This file is part of the Key6 open-source project.
//
// Key6 is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// Key6 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see https://www.gnu.org/licenses.

const Keychain = @import("keychain.zig").Keychain;
const std = @import("std");

/// Result of an attempt to allocate memory for a keychain with
/// `keychain_alloc()`.
pub const KeychainInitResult = extern union {
    success: *anyopaque,
    failure: enum(c_int) {
        invalid_main_password,
        main_password_hashing_error,
        out_of_memory,
    },
};

/// Result of an attempt to store a key in a keychain with
/// `keychain_store_key()`.
pub const KeychainStoreKeyResult = extern union {
    success: *anyopaque,
    failure: enum(c_int) {
        invalid_key,
        invalid_path,
        out_of_memory,
    },
};

/// Result of an attempt to read the password of a key storing in a keychain
/// with `keychain_read_password()`.
pub const KeychainReadPasswordResult = extern union {
    success: ?[*:0]u8,
    failure: enum(c_int) {
        decryption_error,
        keychain_error,
        out_of_memory,
    },
};

/// Size of a `Keychain` struct in bytes.
pub const keychain_size = @sizeOf(Keychain);

/// Allocator by which allocations to and deallocations from the heap are
/// delegated to C's stdlib's `malloc()` and `free()`.
const allocator = std.heap.c_allocator;

export fn keychain_init(
    seed: u64,
    main_password: [*:0]const u8,
    main_password_hasher_memory: u32,
    main_password_hasher_parallelism: u32,
    main_password_hasher_time: u32,
) KeychainInitResult {
    var io = std.Io.Threaded.init(allocator, .{});
    defer io.deinit();
    var rng = std.Random.DefaultPrng.init(seed);
    const main_password_hasher_params = std.crypto.pwhash.argon2.Params{
        .t = main_password_hasher_time,
        .m = main_password_hasher_memory,
        .p = @intCast(main_password_hasher_parallelism),
    };
    const keychain = allocator.create(Keychain) catch
        return .{ .failure = .out_of_memory };
    keychain.* = Keychain.init(
        allocator,
        io.io(),
        rng.random(),
        std.mem.span(main_password),
        main_password_hasher_params,
    ) catch |err| return switch (@TypeOf(err)) {
        Keychain.MainPassword.Error => .{ .failure = .invalid_main_password },
        std.crypto.pwhash.Error => .{ .failure = .main_password_hashing_error },
        else => unreachable,
    };
    return .{ .success = keychain };
}

export fn keychain_store_key(
    keychain: *anyopaque,
    label: [*:0]const u8,
    login: [*:0]const u8,
    password: [*:0]const u8,
    path: ?[*:0]const u8,
) KeychainStoreKeyResult {
    var io = std.Io.Threaded.init(allocator, .{});
    defer io.deinit();
    const typed_keychain: *Keychain = @ptrCast(@alignCast(keychain));
    const typed_path =
        if (path) |p|
            std.Uri.parse(std.mem.span(p)) catch return .{
                .failure = .invalid_path,
            }
        else
            null;
    const key = allocator.create(Keychain.Key) catch
        return .{ .failure = .out_of_memory };
    key.* = typed_keychain.storeKey(
        io.io(),
        std.mem.span(label),
        std.mem.span(login),
        std.mem.span(password),
        typed_path,
    ) catch |err| return switch (@TypeOf(err)) {
        Keychain.Key.Error => .{ .failure = .invalid_key },
        std.mem.Allocator.Error => .{ .failure = .out_of_memory },
        else => unreachable,
    };
    return .{ .success = key };
}

export fn keychain_read_password(
    keychain: *anyopaque,
    key: *anyopaque,
) KeychainReadPasswordResult {
    var io = std.Io.Threaded.init(allocator, .{});
    defer io.deinit();
    const typed_keychain: *Keychain = @ptrCast(@alignCast(keychain));
    const typed_key: *Keychain.Key = @ptrCast(@alignCast(key));
    const typed_password =
        if (typed_keychain.*.readPassword(io.io(), typed_key.*)) |password|
            password orelse return .{ .success = null }
        else |err|
            return switch (@TypeOf(err)) {
                Keychain.Error => .keychain_error,
                std.crypto.errors.AuthenticationError => .decryption_error,
                std.mem.Allocator.Error => .out_of_memory,
                else => unreachable,
            };
    const untyped_password =
        allocator.dupeZ(u8, typed_password) catch return .{
            .failure = .out_of_memory,
        };
    return .{ .success = untyped_password.ptr };
}

export fn keychain_free(keychain: *anyopaque) void {
    var io = std.Io.Threaded.init(allocator, .{});
    defer io.deinit();
    var typed_keychain: *Keychain = @ptrCast(@alignCast(keychain));
    typed_keychain.deinit();
}
