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
_main_password_verify_options: pwhash.argon2.VerifyOptions,
_current_unlock_attempt_count: usize,
_last_activity_time_in_secs: u128,
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

    /// Random bytes for preventing the encryption of the plain password of two
    /// keys from resulting in the same ciphertext.
    salt: [16]u8,

    /// Random bytes for…?
    iv: [12]u8,

    /// Ciphertext from having encrypted the password in plaintext of this key.
    encrypted_password: []const u8,

    /// URI that leads to the site. Usually, is that of a local file or a
    /// website.
    path: ?std.Uri,

    pub const Error = error{
        MalformedID,
        Unlabeled,
        InsufficientCredentials,
    };

    fn init(
        io: std.Io,
        label: []const u8,
        login: []const u8,
        salt: [16]u8,
        iv: [12]u8,
        encrypted_password: []const u8,
        path: ?std.Uri,
    ) @This().Error!Key {
        try validateLabel(label);
        try validateCredentials(login, encrypted_password);
        return .{
            .id = uuid.v7.new(io),
            .label = label,
            .login = login,
            .salt = salt,
            .iv = iv,
            .encrypted_password = encrypted_password,
            .path = path,
        };
    }

    fn validate(self: Key) @This().Error!void {
        try validateID(self.id);
        try validateLabel(self.label);
        try validateCredentials(self.login, self.encrypted_password);
    }

    fn validateID(id: u128) @This().Error!void {
        _ = uuid.urn.deserialize(std.mem.asBytes(&id)) catch
            return @This().Error.MalformedID;
    }

    fn validateLabel(label: []const u8) @This().Error!void {
        if (strings.isBlank(label))
            return @This().Error.Unlabeled;
    }

    fn validateCredentials(
        login: []const u8,
        password: []const u8,
    ) @This().Error!void {
        if (strings.isBlank(login) and strings.isBlank(password))
            return @This().Error.InsufficientCredentials;
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
        params: pwhash.argon2.Params,
    ) pwhash.Error![]const u8 {
        var out: [128]u8 = undefined;
        const options = pwhash.argon2.HashOptions{
            .allocator = allocator,
            .params = params,
        };
        return pwhash.argon2.strHash(main_password, options, &out, io);
    }
};

/// Frees memory allocated by this keychain.
pub fn deinit(self: *Self) void {
    self._keys.deinit();
}

pub const default_max_unlock_attempt_count = 3;

const pwhash = std.crypto.pwhash;
const Self = @This();
const std = @import("std");
const strings = @import("strings.zig");
const uuid = @import("uuid");

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
    main_password_hasher_params: pwhash.argon2.Params,
    max_unlock_attempt_count: usize,
) !Self {
    var csprng_seed: [32]u8 = undefined;
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
        ._last_activity_time_in_secs = 0,
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
    var salt: [12]u8 = undefined;
    self._csprng.fill(&salt);
    var iv: [16]u8 = undefined;
    self._csprng.fill(&iv);
    const key = try Key.init(io, label, login, salt, iv, plain_password, path);
    try self._keys.put(key.id, key);
    return key;
}

/// Reads non-sensitive information about a key with the given ID that's been
/// stored in this keychain. As the credentials of such key are still encrypted
/// even when it's returned, this operation doesn't require that this keychain
/// be unlocked.
pub fn getKey(self: Self, id: u128) Key.Error!?Key {
    try Key.validateID(id);
    return self._keys.get(id);
}

/// Decrypts the encrypted password of the given key. This function requires
/// both that this keychain be unlocked and they to belong to this keychain;
/// otherwise, an error or null is returned, respectively.
pub fn getPlainPassword(self: Self, key: Key) Error!?[]const u8 {
    if (self.isLocked(nowInSecs()))
        return Error.Locked;
    if (!self._keys.contains(key.id))
        return null;
    return key.encrypted_password;
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
    self._last_activity_time_in_secs = now_in_secs;
}

fn isLocked(self: Self, now_in_secs: u128) bool {
    return now_in_secs -
        self._last_activity_time_in_secs >
        self.inactivity_threshold_in_secs;
}

fn nowInSecs(io: std.Io) u128 {
    return @intCast(std.Io.Clock.real.now(io).toSeconds());
}

const argon2_params = @import("argon2_params.zig");
const permutator = @import("permutator.zig");

test "Key.validate(): errors if ID isn't a UUID v7" {
    var key = sampleKey();
    const uuidV1 = 271512419355585897264112360044229548004;
    const uuidV2 = 46389061844604403514171447268;
    const uuidV3 = 192008915286352178671835060405176363243;
    const uuidV5 = 276146808210084729002700941631111409175;
    const uuidV6 = 41337787919363718083970579157359777764;
    inline for (&.{
        0,
        uuidV1,
        uuidV2,
        uuidV3,
        uuid.v4.new(std.testing.io),
        uuidV5,
        uuidV6,
    }) |id| {
        key.id = id;
        try std.testing.expectError(Key.Error.MalformedID, key.validate());
    }
}

test "Key.init(): errors if both credentials are blank" {
    var key = sampleKey();
    var backing_credentials = [_][]const u8{ "", " ", "  " };
    var credentials: [][]const u8 = backing_credentials[0..];
    var credential_iter = permutator.Iterator([]const u8, 2).init(&credentials);
    while (credential_iter.next()) |permutation| {
        key.login = permutation[0];
        key.encrypted_password = permutation[1];
        try std.testing.expectError(
            Key.Error.InsufficientCredentials,
            Key.init(
                std.testing.io,
                key.label,
                key.login,
                key.salt,
                key.iv,
                key.encrypted_password,
                key.path,
            ),
        );
    }
}

test "init(): errors on blank main password" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const main_password = "appleseed";
    const keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    try std.testing.expectEqual(
        null,
        std.mem.indexOf(u8, keychain._main_password_hash, main_password),
    );
}

test "init(): main password isn't discarded" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const main_password = "appleseed";
    _ = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    try std.testing.expectEqual("appleseed", main_password);
}

test "unlock(): errors on exceeding unsuccessful attempts" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        "appleseed",
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    while (keychain._current_unlock_attempt_count <
        keychain.max_unlock_attempt_count)
        try keychain.unlock(std.testing.io, "");
    try std.testing.expectError(
        Error.TooManyUnlockAttempts,
        keychain.unlock(std.testing.io, ""),
    );
}

test "unlock(): unlocks if given the correct main password" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const main_password = "appleseed";
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    try keychain.unlock(std.testing.io, main_password);
}

test "unlock(): doesn't require main password within inactivity threshold" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const main_password = "appleseed";
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    keychain.inactivity_threshold_in_secs =
        std.math.maxInt(@TypeOf(keychain.inactivity_threshold_in_secs));
    try keychain.unlock(std.testing.io, main_password);
    try keychain.unlock(std.testing.io, null);
}

test "unlock(): requires main password after inactivity threshold" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const main_password = "appleseed";
    var keychain = try init(
        std.testing.allocator,
        std.testing.io,
        default_prng.random(),
        main_password,
        argon2_params.min,
        default_max_unlock_attempt_count,
    );
    try keychain.unlock(std.testing.io, main_password);
    try std.testing.expectError(
        Error.Locked,
        keychain.unlock(std.testing.io, null),
    );
}

fn sampleKey() Key {
    return .{
        .id = uuid.v7.new(std.testing.io),
        .label = "key6",
        .login = "john@appleseed.com",
        .salt = [_]u8{0} ** 16,
        .iv = [_]u8{0} ** 12,
        .encrypted_password = "4pp3s33d",
        .path = null,
    };
}
