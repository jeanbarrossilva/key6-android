// there are no visibility modifiers in Zig. we, then, levearage an old-time's
// technique; a blessing bestowed upon us by the gods of the Olympus: the
// underscore prefix (_).
//
// fields that SHOULDN'T be meddled with have their name beginning with an
// underscore. pretty please, DON'T touch these fields. (or do, but at your own
// risk.) :p

/// Cryptographically-secure pseudorandom number generator (CSPRNG) by which
/// AES-256-GCM nonces and tags are generated for encrypting the secrets of
/// keys.
_csprng: std.Random.DefaultCsprng,

/// Argon2 hash of this keychain's main password.
_main_password_hash: []const u8,

/// Actual amount of unsuccessful attempts to unlock this keychain.
_current_unlock_attempt_count: usize,

/// Unix-epoch-based duration in seconds since this keychain was last active.
/// Being "active" means performing any operation that would require entering
/// the main password when the keychain is inactive (e.g., reading the secrets
/// of a key).
_last_activity_time_in_secs: u128,

/// Maximum amount of attempts to enter the main password. Once incorrect
/// passwords have been provided more times than the quantity assigned to this
/// field, an error will be returned by the function of this keychain that
/// tried to unlock it.
max_unlock_attempt_count: usize,

/// Duration in seconds since the last unlock from which an unlock will be
/// required again for reading the secrets of keys and removing keys stored in
/// this keychain.
inactivity_threshold_in_secs: u128,

/// Utilities for dealing with a keychain's main password.
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

    fn validate(main_password: []const u8) Error!void {
        try requireNonBlank(main_password);
        try requireNonOverlyConsecutive(main_password);
    }

    fn requireNonBlank(main_password: []const u8) Error!void {
        if (strings.isBlank(main_password))
            return Error.Blank;
    }

    fn requireNonOverlyConsecutive(main_password: []const u8) Error!void {
        var consecution_len: usize = 0;
        for (main_password[1..], 1..) |curr_char, i| {
            const prev_char = main_password[i - 1];
            if (curr_char != prev_char) {
                consecution_len = 0;
                continue;
            }
            if (consecution_len == max_main_password_consecution_len - 1)
                return Error.TooManyConsecutions;
            consecution_len += 1;
        }
    }
};

pub const default_max_unlock_attempt_count = 3;

const Self = @This();
const std = @import("std");
const strings = @import("strings.zig");

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
    rng: std.Random,
    main_password: []const u8,
    max_unlock_attempt_count: usize,
) !Self {
    var csprng_seed: [32]u8 = undefined;
    rng.bytes(&csprng_seed);
    try MainPassword.validate(main_password);
    return .{
        ._csprng = .init(csprng_seed),
        ._main_password_hash = "4ppl3s33d",
        ._current_unlock_attempt_count = 0,
        ._last_activity_time_in_secs = 0,
        .max_unlock_attempt_count = max_unlock_attempt_count,
        .inactivity_threshold_in_secs = 0,
    };
}

pub fn unlock(
    self: *Self,
    io: std.Io,
    main_password: []const u8,
) error{TooManyUnlockAttempts}!void {
    const now: u128 = @intCast(std.Io.Clock.real.now(io).toSeconds());
    if (self.inactivity_threshold_in_secs > 0) {
        const inactivity_in_secs = now - self._last_activity_time_in_secs;
        if (inactivity_in_secs <= self.inactivity_threshold_in_secs)
            return;
    }

    // this condition makes no sense, no. will change it very soon.
    if (std.mem.eql(u8, self._main_password_hash, main_password)) {
        self._current_unlock_attempt_count = 0;
        self._last_activity_time_in_secs = now;
        return;
    }

    if (self._current_unlock_attempt_count == self.max_unlock_attempt_count) {
        self._current_unlock_attempt_count = 0;
        return error.TooManyUnlockAttempts;
    }
    self._current_unlock_attempt_count += 1;
}

test "init(): errors on blank main password" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    inline for (&.{ "", " ", "  " }) |main_password|
        try std.testing.expectError(
            MainPassword.Error.Blank,
            init(
                default_prng.random(),
                main_password,
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
                default_prng.random(),
                main_password,
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
        default_prng.random(),
        main_password,
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
        default_prng.random(),
        main_password,
        default_max_unlock_attempt_count,
    );
    try std.testing.expectEqual("appleseed", main_password);
}

test "unlock(): errors on exceeding unsuccessful attempts" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var keychain = try init(
        default_prng.random(),
        "appleseed",
        default_max_unlock_attempt_count,
    );
    while (keychain._current_unlock_attempt_count <
        keychain.max_unlock_attempt_count)
        try keychain.unlock(std.testing.io, "");
    try std.testing.expectError(
        error.TooManyUnlockAttempts,
        keychain.unlock(std.testing.io, ""),
    );
}

test "unlock(): unlocks" {
    var default_prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var keychain = try init(
        default_prng.random(),
        "appleseed",
        default_max_unlock_attempt_count,
    );
    try keychain.unlock(std.testing.io, "appleseed");
}
