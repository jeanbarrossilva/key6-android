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

/// Maximum amount of attempts to enter the main password. Once incorrect
/// passwords have been provided more times than the quantity assigned to this
/// field, an error will be returned by the function of this keychain that
/// tried to unlock it.
max_unlock_attempt_count: usize,

/// Duration in seconds since the last unlock from which an unlock will be
/// required again for reading the credentials of keys and removing keys stored
/// in this keychain.
inactivity_threshold_in_secs: u128,

_allocator: std.mem.Allocator,
_csprng: std.Random.DefaultCsprng,
_main_password_hash: []const u8,
_main_password_verify_options: argon2.VerifyOptions,
_current_unlock_attempt_count: usize,
_last_activity_timestamp_in_secs: u128,
_keys: std.AutoHashMap(u128, Key),

/// Failure resulted from attempting to perform an operation related strictly to
/// a keychain.
pub const Error = error{
    /// The amount of unsuccessful attempts to unlock the keychain was greater
    /// than the maximum quantity defined for that specific keychain.
    TooManyUnlockAttempts,

    /// The keychain was attempted to be unlocked without its main password
    /// while the keychain was locked.
    Locked,
};

/// Entry specific to a given keychain, consisting of user metadata regarding
/// authentication at a specific site.
pub const Key = struct {
    /// Identifier of this key, unique in the keychain in which this key is
    /// stored.
    id: u128,

    /// Arbitrary, user-defined string used for distinguishing one key from
    /// another from the user's point of view. This doesn't have to be unique,
    /// as the _truly_ unique identifier of a key is its `id`.
    label: []const u8,

    /// Identifier of the user at the site. Usually, consists of an e-mail, a
    /// username or a phone number.
    login: []const u8,

    /// Ciphertext from having encrypted the password in plaintext of this key.
    credential: ?Credential,

    /// URI that leads to the site. Usually, is that of a local file or a
    /// website.
    path: ?std.Uri,

    /// Encrypted password for authenticating at a site.
    pub const Credential = struct {
        /// 256-bit sequence generated randomly by a CSPRNG, used to encrypt
        /// the password.
        key: [Aes256Gcm.key_length]u8,

        /// Random bytes for producing different ciphertexts when encrypting
        /// two equal paswords. This is an input for encryption and, afterward,
        /// decryption.
        iv: [Aes256Gcm.nonce_length]u8,

        /// Bytes generated after encryption of the password, with which the
        /// encrypted password can be decrypted and ensured that no external
        /// attacker tampered with it.
        authentication_tag: [Aes256Gcm.tag_length]u8,

        /// Encrypted contents of this credential.
        ciphertext: []const u8,

        const associated_data = "";

        fn decrypt(
            self: Credential,
            allocator: std.mem.Allocator,
        ) ![]const u8 {
            const password = try allocator.alloc(u8, self.ciphertext.len);
            try Aes256Gcm.decrypt(
                password,
                self.ciphertext,
                self.authentication_tag,
                associated_data,
                self.iv,
                self.key,
            );
            return password;
        }

        fn deinit(self: Credential, allocator: std.mem.Allocator) void {
            allocator.free(self.ciphertext);
        }

        fn encrypt(
            allocator: std.mem.Allocator,
            csprng: *std.Random.DefaultCsprng,
            password: []const u8,
            iv: [12]u8,
        ) error{OutOfMemory}!Credential {
            var key: [Aes256Gcm.key_length]u8 = undefined;
            csprng.fill(&key);
            const ciphertext = try allocator.alloc(u8, password.len);
            var authentication_tag: [Aes256Gcm.tag_length]u8 = undefined;
            Aes256Gcm.encrypt(
                ciphertext,
                &authentication_tag,
                password,
                associated_data,
                iv,
                key,
            );
            return .{
                .key = key,
                .iv = iv,
                .authentication_tag = authentication_tag,
                .ciphertext = ciphertext,
            };
        }
    };

    /// Failure that may occur while initializing a key, depending on the
    /// arguments passed in by the caller. Such an error will *never* be
    /// returned when *retrieving* a key, but may happen when storing one, due
    /// to the arbitrarity of the user-provided arguments.
    pub const Error = error{
        /// The key's ID isn't a UUID v7. With v7 UUIDs, apart from them being
        /// sufficiently unique, we can sort keys based on the time at which
        /// they were stored in the keychain.
        MalformedID,

        /// The key's label was left blank. An unlabeled key would be confusing
        /// and significantly difficult to distinguish from other keys, given
        /// that its ID isn't user-facing (and, event if it was, doesn't give
        /// some human-readable clue about *which* key it identifies).
        Unlabeled,

        /// The key contains neither login nor password. It is required that one
        /// of the two isn't blank, since the purpose of a key is to store
        /// *some* authentication information.
        Insufficient,
    };

    /// Represents a "level" in which a key has been given information in order
    /// for such key to be sufficient. In case none of the three levels are that
    /// of the key and it gets validated by `validate()` afterward, an error
    /// will be returned.
    pub const Sufficiency = enum {
        /// A non-blank login and a blank password were provided to the key.
        contains_login_only,

        /// A blank login and a non-blank password were provided to the key.
        contains_credential_only,

        /// A non-blank login and a non-blank password were provided to the key.
        contains_login_and_credential,
    };

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        csprng: *std.Random.DefaultCsprng,
        label: []const u8,
        login: []const u8,
        password: []const u8,
        path: ?std.Uri,
    ) !Key {
        try validateLabel(label);
        const sufficiency = validateSufficiency(login, password) catch |err|
            return err;
        var iv: [12]u8 = undefined;
        csprng.fill(&iv);
        return .{
            .id = @bitCast(zuid.new.v7(io)),
            .label = label,
            .login = login,
            .credential = switch (sufficiency) {
                .contains_credential_only,
                .contains_login_and_credential,
                => try .encrypt(allocator, csprng, password, iv),
                .contains_login_only,
                => null,
            },
            .path = path,
        };
    }

    fn validate(self: Key) @This().Error!void {
        try validateID(self.id);
        try validateLabel(self.label);
        const credential_ciphertext =
            if (self.credential) |credential| credential.ciphertext else "";
        _ = try validateSufficiency(self.login, credential_ciphertext);
    }

    fn deinit(self: Key, allocator: std.mem.Allocator) void {
        const credential = self.credential orelse return;
        credential.deinit(allocator);
    }

    fn validateID(id: u128) @This().Error!void {
        const uuid: zuid.UUID = @bitCast(id);
        if (uuid.version != 7)
            return @This().Error.MalformedID;
    }

    fn validateLabel(label: []const u8) @This().Error!void {
        if (strings.isBlank(label))
            return @This().Error.Unlabeled;
    }

    fn validateSufficiency(
        login: []const u8,
        password: []const u8,
    ) @This().Error!Sufficiency {
        const is_login_blank = strings.isBlank(login);
        const is_password_blank = strings.isBlank(password);
        return if (is_login_blank and is_password_blank)
            @This().Error.Insufficient
        else if (is_login_blank)
            .contains_login_only
        else
            .contains_credential_only;
    }
};

/// Static utilities for dealing with a keychain's main password.
pub const MainPassword = struct {
    /// Error related to the main password assigned to a keychain.
    pub const Error = error{
        /// The main password contains either no characters whatsoever or only
        /// spaces.
        Blank,

        /// The main password contains characters repeated consecutively more
        /// than 4 times. Using such a password would impact the security of the
        /// keychain negatively by making brute-force attacks easier.
        TooManyConsecutions,
    };

    fn validate(main_password: []const u8) @This().Error!void {
        try requireNonBlank(main_password);
        try requireNonOverlyConsecutive(main_password);
    }

    fn requireNonBlank(main_password: []const u8) @This().Error!void {
        if (strings.isBlank(main_password))
            return @This().Error.Blank;
    }

    fn requireNonOverlyConsecutive(
        main_password: []const u8,
    ) @This().Error!void {
        var consecution_len: usize = 0;
        for (main_password[1..], 1..) |curr_char, i| {
            const prev_char = main_password[i - 1];
            if (curr_char != prev_char) {
                consecution_len = 0;
                continue;
            }
            consecution_len += 1;
            if (consecution_len == max_main_password_consecution_len)
                return @This().Error.TooManyConsecutions;
        }
    }

    fn hash(
        allocator: std.mem.Allocator,
        io: std.Io,
        main_password: []const u8,
        params: argon2.Params,
    ) pwhash.Error![]const u8 {
        var out: [128]u8 = undefined;
        const options = argon2.HashOptions{
            .allocator = allocator,
            .params = params,
        };
        return argon2.strHash(main_password, options, &out, io);
    }
};

pub const default_max_unlock_attempt_count = 3;

const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const argon2 = pwhash.argon2;
const crypto = std.crypto;
const pwhash = crypto.pwhash;
const Self = @This();
const std = @import("std");
const strings = @import("strings.zig");
const zuid = @import("zuid");

const max_main_password_consecution_len = 4;

/// Initializes a keychain with the given main password given in plaintext. A
/// hash of such password is calculated through Argon2, and used to encrypt the
/// keys stored in the keychain.
///
/// The main password is constrained to some rules regarding its contents, given
/// that bypassing these rules would result in an insecure keychain. A balance
/// between convenience and security is tried to be maintained. The rules are:
///
/// 1. There MUST be at least 1 character.
/// 2. There MUST be at least 1 non-space character.
/// 3. There MUST NOT be more than 4 consecutive repetitions of the same
///    character.
///
/// Apart from following these rules, the caller of this initializer is
/// responsible for discarding the given password afterward.
///
/// The passed-in RNG is not that of the keychain itself; rather, its only role
/// in this initialization is to generate the seed for the keychain's CSPRNG.
pub fn init(
    allocator: std.mem.Allocator,
    io: std.Io,
    rng: std.Random,
    main_password: []const u8,
    main_password_hasher_params: argon2.Params,
    max_unlock_attempt_count: usize,
) !Self {
    var csprng_seed: [std.Random.DefaultCsprng.secret_seed_length]u8 =
        undefined;
    rng.bytes(&csprng_seed);
    try MainPassword.validate(main_password);
    return .{
        .max_unlock_attempt_count = max_unlock_attempt_count,
        .inactivity_threshold_in_secs = 0,
        ._allocator = allocator,
        ._csprng = .init(csprng_seed),
        ._main_password_hash = try MainPassword.hash(
            allocator,
            io,
            main_password,
            main_password_hasher_params,
        ),
        ._main_password_verify_options = .{ .allocator = allocator },
        ._current_unlock_attempt_count = 0,
        ._last_activity_timestamp_in_secs = 0,
        ._keys = .init(allocator),
    };
}

/// Encrypts and stores the credentials for a given site, alongside additional
/// user-facing information such as a label and a path. All posterior reads to
/// sensitive data will require that this keychain be unlocked, and may prompt
/// the user to provide this keychain's main password.
///
/// This function returns the ID generated for the stored key, with which the
/// key can be retrieved later by calling `getKey()`.
pub fn storeKey(
    self: *Self,
    io: std.Io,
    label: []const u8,
    login: []const u8,
    plain_password: []const u8,
    path: ?std.Uri,
) !u128 {
    const key = try Key.init(
        self._allocator,
        io,
        &self._csprng,
        label,
        login,
        plain_password,
        path,
    );
    try self._keys.put(key.id, key);
    return key.id;
}

/// Reads non-sensitive information about a key with the given ID that's been
/// stored in this keychain. As the credentials of such key are still encrypted
/// even when it's returned, this operation doesn't require that this keychain
/// be unlocked.
///
/// This function will error in case the ID is malformed, or return null if it
/// isn't that of a key stored in this keychain.
pub fn findKey(self: Self, id: u128) Key.Error!?Key {
    try Key.validateID(id);
    return self._keys.get(id);
}

/// Decrypts the credential of the given key. This function requires both that
/// this keychain be unlocked and such key belong to this keychain; otherwise,
/// an error or null is returned, respectively.
pub fn readPassword(self: Self, io: std.Io, key: Key) !?[]const u8 {
    if (self.isLocked(nowInSecs(io)))
        return Error.Locked;
    if (!self._keys.contains(key.id))
        return null;
    if (key.credential) |credential|
        return try credential.decrypt(self._allocator);
    return null;
}

/// Allows for reading the credentials of keys from now on, until the duration
/// defined as the inactivity threshold of this keychain. After such time,
/// attempting to read those credentials without having called this function
/// again will result in an error being thrown.
///
/// This function is a no-op in case this keychain is already unlocked _and_ no
/// main password (i.e., a null one) is passed in.
pub fn unlock(self: *Self, io: std.Io, main_password: ?[]const u8) Error!void {
    const now_in_secs = nowInSecs(io);
    const mp = main_password orelse
        return if (!self.isLocked(now_in_secs)) {} else Error.Locked;
    pwhash.argon2.strVerify(
        self._main_password_hash,
        mp,
        self._main_password_verify_options,
        io,
    ) catch |err| switch (err) {
        std.crypto.errors.Error.InvalidEncoding,
        std.crypto.errors.Error.PasswordVerificationFailed,
        => {
            if (self._current_unlock_attempt_count ==
                self.max_unlock_attempt_count)
            {
                self._current_unlock_attempt_count = 0;
                return Error.TooManyUnlockAttempts;
            }
            self._current_unlock_attempt_count += 1;
            return;
        },
        else => {},
    };
    self._current_unlock_attempt_count = 0;
    self._last_activity_timestamp_in_secs = now_in_secs;
}

/// Frees memory allocated by this keychain.
pub fn deinit(self: *Self) void {
    var key_iter = self._keys.valueIterator();
    while (key_iter.next()) |key|
        key.deinit(self._allocator);
    self._keys.deinit();
}

fn isLocked(self: Self, now_in_secs: u128) bool {
    return now_in_secs -
        self._last_activity_timestamp_in_secs >
        self.inactivity_threshold_in_secs;
}

fn nowInSecs(io: std.Io) u128 {
    return @intCast(std.Io.Clock.real.now(io).toSeconds());
}

const argon2_params = @import("argon2_params.zig");
const permutator = @import("permutator.zig");

var default_csprng = std.Random.DefaultCsprng.init(
    [_]u8{0} ** std.Random.DefaultCsprng.secret_seed_length,
);
var default_prng = std.Random.DefaultPrng.init(0);
const default_main_password = "appleseed";
const default_password = "password123";

test "Key.validate(): errors if ID isn't a UUID v7" {
    var key = initSampleKey();
    defer key.deinit(std.testing.allocator);
    const ids = [_]u128{
        0,
        @bitCast(zuid.new.v1(std.testing.io)),
        @bitCast(zuid.new.v4(std.testing.io)),
        @bitCast(zuid.new.v6(std.testing.io)),
    };
    inline for (ids) |id| {
        key.id = id;
        try std.testing.expectError(Key.Error.MalformedID, key.validate());
    }
}

test "Key.init(): generated ID is always valid" {
    for (0..255) |_| {
        const key = initSampleKey();
        defer key.deinit(std.testing.allocator);
        try Key.validateID(key.id);
    }
}

test "Key.init(): errors if both credentials are blank" {
    var key = initSampleKey();
    defer key.deinit(std.testing.allocator);
    var backing_credentials = [_][]const u8{ "", " ", "  " };
    var credentials: [][]const u8 = backing_credentials[0..];
    var credential_iter = permutator.Iterator([]const u8, 2).init(&credentials);
    while (credential_iter.next()) |permutation| {
        const password = permutation[1];
        key.login = permutation[0];
        try std.testing.expectError(
            Key.Error.Insufficient,
            Key.init(
                std.testing.allocator,
                std.testing.io,
                &default_csprng,
                key.label,
                key.login,
                password,
                key.path,
            ),
        );
    }
}

test "init(): errors on blank main password" {
    inline for (&.{ "", " ", "  " }) |main_password|
        try std.testing.expectError(
            MainPassword.Error.Blank,
            init(
                std.testing.allocator,
                std.testing.io,
                default_prng.random(),
                main_password,
                argon2_params.min,
                default_max_unlock_attempt_count,
            ),
        );
}

test "init(): errors on main password with 5+ character consecutions" {
    inline for (&.{
        try strings.repeat(
            "a",
            std.testing.allocator,
            max_main_password_consecution_len + 1,
        ),
        try strings.repeat(
            "b",
            std.testing.allocator,
            max_main_password_consecution_len * 2,
        ),
    }) |main_password| {
        try std.testing.expectError(
            MainPassword.Error.TooManyConsecutions,
            init(
                std.testing.allocator,
                std.testing.io,
                default_prng.random(),
                main_password,
                argon2_params.min,
                default_max_unlock_attempt_count,
            ),
        );
        std.testing.allocator.free(main_password);
    }
}

test "init(): main password isn't in hash" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    try std.testing.expectEqual(
        null,
        std.mem.indexOf(
            u8,
            keychain._main_password_hash,
            default_main_password,
        ),
    );
}

test "init(): main password isn't discarded" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    try std.testing.expectEqual("appleseed", default_main_password);
}

test "unlock(): errors on exceeding unsuccessful attempts" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        "appleseed",
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    while (keychain._current_unlock_attempt_count <
        keychain.max_unlock_attempt_count)
        try keychain.unlock(std.testing.io, "");
    try std.testing.expectError(
        Error.TooManyUnlockAttempts,
        keychain.unlock(std.testing.io, ""),
    );
}

test "unlock(): unlocks if given the correct main password" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    try keychain.unlock(std.testing.io, default_main_password);
}

test "unlock(): doesn't require main password within inactivity threshold" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    makeAlwaysActive(&keychain);
    try keychain.unlock(std.testing.io, default_main_password);
    try keychain.unlock(std.testing.io, null);
}

test "unlock(): requires main password after inactivity threshold" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    try keychain.unlock(std.testing.io, default_main_password);
    try std.testing.expectError(
        Error.Locked,
        keychain.unlock(std.testing.io, null),
    );
}

test "storeKey(): key's password isn't stored in plaintext" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    const template_key = initSampleKey();
    defer template_key.deinit(std.testing.allocator);
    const keyID = try keychain.storeKey(
        std.testing.io,
        template_key.label,
        template_key.login,
        default_password,
        template_key.path,
    );
    const stored_key = (try keychain.findKey(keyID)).?;
    try std.testing.expect(
        std.mem.containsAtLeast(
            u8,
            stored_key.credential.?.ciphertext,
            0,
            default_password,
        ),
    );
}

test "readPassword(): returns null if key isn't stored" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    makeAlwaysActive(&keychain);
    const absent_key = initSampleKey();
    defer absent_key.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        null,
        try keychain.readPassword(std.testing.io, absent_key),
    );
}

test "readPassword(): reads password of stored key" {
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        default_main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    defer keychain.deinit();
    makeAlwaysActive(&keychain);
    const template_key = initSampleKey();
    defer template_key.deinit(std.testing.allocator);
    const keyID = try keychain.storeKey(
        std.testing.io,
        template_key.label,
        template_key.login,
        default_password,
        template_key.path,
    );
    const stored_key = (try keychain.findKey(keyID)).?;
    const read_password =
        (try keychain.readPassword(std.testing.io, stored_key)).?;
    defer std.testing.allocator.free(read_password);
    try std.testing.expectEqualSlices(u8, default_password, read_password);
}

fn initSampleKey() Key {
    const label = "Key6";
    const login = "john@appleseed.com";
    const path: ?std.Uri = null;
    return Key.init(
        std.testing.allocator,
        std.testing.io,
        &default_csprng,
        label,
        login,
        default_password,
        path,
    ) catch unreachable;
}

fn makeAlwaysActive(keychain: *Self) void {
    keychain.inactivity_threshold_in_secs =
        std.math.maxInt(@TypeOf(keychain.inactivity_threshold_in_secs));
}
