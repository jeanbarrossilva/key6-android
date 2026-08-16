const argon2_params = @import("utils/argon2_params.zig");
const Keychain = @import("Keychain.zig").Keychain;
const permutator = @import("utils/permutator.zig");
const std = @import("std");
const strings = @import("utils/strings.zig");
const zuid = @import("zuid");

const main_password = "appleseed";
const key_password = "password123";
var csprng = std.Random.DefaultCsprng.init(
    [_]u8{0} ** std.Random.DefaultCsprng.secret_seed_length,
);
var prng = std.Random.DefaultPrng.init(0);

test "Key.validate(): errors if ID isn't a UUID v7" {
    var key = initSampleKey();
    defer key._deinit(std.testing.allocator);
    const ids = [_]u128{
        0,
        @bitCast(zuid.new.v1(std.testing.io)),
        @bitCast(zuid.new.v4(std.testing.io)),
        @bitCast(zuid.new.v6(std.testing.io)),
    };
    inline for (ids) |id| {
        key.id = id;
        try std.testing.expectError(
            Keychain.Key.Error.MalformedID,
            key._validate(),
        );
    }
}

test "Key.init(): generated ID is always valid" {
    for (0..255) |_| {
        const key = initSampleKey();
        defer key._deinit(std.testing.allocator);
        try key._validate();
    }
}

test "Key.init(): errors if both credentials are blank" {
    var key = initSampleKey();
    defer key._deinit(std.testing.allocator);
    var backing_credentials = [_][]const u8{ "", " ", "  " };
    var credentials: [][]const u8 = backing_credentials[0..];
    var credential_iter = permutator.Iterator([]const u8, 2).init(&credentials);
    while (credential_iter.next()) |permutation| {
        const password = permutation[1];
        key.login = permutation[0];
        try std.testing.expectError(
            Keychain.Key.Error.Insufficient,
            Keychain.Key._init(
                std.testing.allocator,
                std.testing.io,
                &csprng,
                key.label,
                key.login,
                password,
                key.path,
            ),
        );
    }
}

test "init(): errors on blank main password" {
    inline for (&.{ "", " ", "  " }) |mp|
        try std.testing.expectError(
            Keychain.MainPassword.Error.Blank,
            Keychain.init(
                std.testing.allocator,
                std.testing.io,
                prng.random(),
                mp,
                argon2_params.min,
            ),
        );
}

test "init(): errors on main password with 5+ character consecutions" {
    inline for (&.{
        try strings.repeat(
            "a",
            std.testing.allocator,
            Keychain.max_main_password_consecution_len + 1,
        ),
        try strings.repeat(
            "b",
            std.testing.allocator,
            Keychain.max_main_password_consecution_len * 2,
        ),
    }) |mp| {
        try std.testing.expectError(
            Keychain.MainPassword.Error.TooManyConsecutions,
            Keychain.init(
                std.testing.allocator,
                std.testing.io,
                prng.random(),
                mp,
                argon2_params.min,
            ),
        );
        std.testing.allocator.free(mp);
    }
}

test "init(): main password isn't in hash" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    try std.testing.expectEqual(
        null,
        std.mem.indexOf(u8, keychain.main_password_hash, main_password),
    );
}

test "init(): main password isn't discarded" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    try std.testing.expectEqual("appleseed", main_password);
}

test "unlock(): errors on exceeding unsuccessful attempts" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        "appleseed",
        argon2_params.min,
    );
    defer keychain.deinit();
    while (keychain.current_unlock_attempt_count <
        keychain.max_unlock_attempt_count)
        try keychain.unlock(std.testing.io, "");
    try std.testing.expectError(
        Keychain.Error.TooManyUnlockAttempts,
        keychain.unlock(std.testing.io, ""),
    );
}

test "unlock(): unlocks if given the correct main password" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    try keychain.unlock(std.testing.io, main_password);
}

test "unlock(): doesn't require main password within inactivity threshold" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    disableAutoLock(&keychain);
    try keychain.unlock(std.testing.io, main_password);
    try keychain.unlock(std.testing.io, null);
}

test "unlock(): requires main password after inactivity threshold" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    try keychain.unlock(std.testing.io, main_password);
    try std.testing.expectError(
        Keychain.Error.Locked,
        keychain.unlock(std.testing.io, null),
    );
}

test "storeKey(): key's password isn't stored in plaintext" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    const template_key = initSampleKey();
    defer template_key._deinit(std.testing.allocator);
    const stored_key = try keychain.storeKey(
        std.testing.io,
        template_key.label,
        template_key.login,
        key_password,
        template_key.path,
    );
    try std.testing.expect(
        std.mem.containsAtLeast(
            u8,
            stored_key.credential.?.ciphertext,
            0,
            key_password,
        ),
    );
}

test "readPassword(): returns null if key isn't stored" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    disableAutoLock(&keychain);
    const absent_key = initSampleKey();
    defer absent_key._deinit(std.testing.allocator);
    try std.testing.expectEqual(
        null,
        try keychain.readPassword(std.testing.io, absent_key),
    );
}

test "readPassword(): reads password of stored key" {
    var keychain = try Keychain.init(
        std.testing.allocator,
        std.testing.io,
        prng.random(),
        main_password,
        argon2_params.min,
    );
    defer keychain.deinit();
    disableAutoLock(&keychain);
    const template_key = initSampleKey();
    defer template_key._deinit(std.testing.allocator);
    const stored_key = try keychain.storeKey(
        std.testing.io,
        template_key.label,
        template_key.login,
        key_password,
        template_key.path,
    );
    const read_password =
        (try keychain.readPassword(std.testing.io, stored_key)).?;
    defer std.testing.allocator.free(read_password);
    try std.testing.expectEqualSlices(u8, key_password, read_password);
}

fn initSampleKey() Keychain.Key {
    const label = "Key6";
    const login = "john@appleseed.com";
    const path: ?std.Uri = null;
    return Keychain.Key._init(
        std.testing.allocator,
        std.testing.io,
        &csprng,
        label,
        login,
        key_password,
        path,
    ) catch unreachable;
}

fn disableAutoLock(keychain: *Keychain) void {
    keychain.inactivity_threshold_in_secs =
        std.math.maxInt(@TypeOf(keychain.inactivity_threshold_in_secs));
}
