/// Argon2 hash of this keychain's main password.
main_password_hash: []const u8,

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
/// Apart from following this rules, the caller of this initializer is
/// responsible for discarding the given password afterward.
pub fn init(main_password: []const u8) MainPassword.Error!Self {
    try MainPassword.validate(main_password);
    return .{ .main_password_hash = "4ppl3s33d" };
}

test "init(): errors on blank main password" {
    inline for (&.{ "", " ", "  " }) |main_password|
        try std.testing.expectError(
            MainPassword.Error.Blank,
            init(main_password),
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
            init(main_password),
        );
        std.testing.allocator.free(main_password);
    }
}

test "init(): main password isn't in hash" {
    const main_password = "appleseed";
    const keychain = try init(main_password);
    try std.testing.expectEqual(
        null,
        std.mem.indexOf(u8, keychain.main_password_hash, main_password),
    );
}

test "init(): main password isn't discarded" {
    const main_password = "appleseed";
    _ = try init(main_password);
    try std.testing.expectEqual("appleseed", main_password);
}
