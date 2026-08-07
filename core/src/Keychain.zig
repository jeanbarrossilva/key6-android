/// Maximum amount of attempts to enter the main password. Once incorrect
/// passwords have been provided more times than the quantity assigned to this
/// field, an error will be returned by the function of this keychain that
/// tried to unlock it.
max_unlock_attempt_count: usize,

/// Duration in seconds since the last unlock from which an unlock will be
/// required again for reading the secrets of keys and removing keys stored in
/// this keychain.
inactivity_threshold_in_secs: u128,

_allocator: std.mem.Allocator,
_csprng: std.Random.DefaultCsprng,
_main_password_hash: []const u8,
_main_password_verify_options: pwhash.argon2.VerifyOptions,
_current_unlock_attempt_count: usize,
_last_activity_time_in_secs: u128,

/// Failure resulted from attempting to perform an operation related strictly to
/// a keychain.
pub const Error = error{TooManyUnlockAttempts};

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

const pwhash = std.crypto.pwhash;
const Self = @This();
const std = @import("std");
const strings = @import("strings.zig");

const default_max_unlock_attempt_count = 3;
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
/// 3. There MUST NOT be 4 or more consecutive repetitions of the same
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
    };
}

pub fn unlock(self: *Self, io: std.Io, main_password: []const u8) !void {
    const now_in_secs: u128 = @intCast(std.Io.Clock.real.now(io).toSeconds());
    if (!self.isLocked(now_in_secs))
        return;
    pwhash.argon2.strVerify(
        self._main_password_hash,
        main_password,
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

const argon2_params = @import("argon2_params.zig");

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

test "unlock(): unlocks" {
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
