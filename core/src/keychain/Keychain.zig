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

// API + implementation
// -----------------------------------------------------------------------------

/// Actor responsible for the main feature of Key6: storing, encrypting and
/// retrieving authentication information of the user at various sites locally.
/// Besides securing these data, allows for generating random passwords with
/// custom constraints and, consequently, providing greater safety against
/// attacks targeting these sites.
///
/// Sites are referred to throughout this entire documentation. Sites are files
/// or services accessible via a login and/or a password. Despite their name,
/// they are not limited to *web*sites; they can also be, e.g., a compressed
/// file requiring a password.
///
/// Keys, on the other hand, are the combination of these information for
/// authentication at a specific site. When they are stored in a keychain, a
/// unique identifier is generated for them automatically, and returned as a
/// string. As it is an implementation detail and subject to change, no
/// assumptions on the format of this string should be made; however, as of v1
/// of Key6, every key identifier is a UUID v7.
///
/// ## Locking and unlocking
///
/// The sole purpose of a keychain is to make the task of storing passwords and
/// generating strong, new ones easier, removing the burden of having to
/// remember them all from the user. Password-wise, with the process of
/// generating passwords automated, the user's prominence to cyberattacks may be
/// significantly reduced.
///
/// To achieve this goal, keychains require a single, main password. This
/// password is the only one the user needs to remember, and will be used to
/// unlock the keychain and read passwords stored in it. The keychain *may*
/// require an unlock when
///
/// 1. reading the password of one of its keys; and
/// 2. removing one of its keys.
///
/// The main password of the keychain *may* be requested, with a leniency of
/// `max_unlock_attempt_count` attempts for the correct password to be provided;
/// in case that maximum is exceeded, with all requests having resulted in
/// incorrect passwords, an exception will be thrown, preventing the operation
/// from being performed.
///
/// The main password *will not* be requested, however, if the time passed since
/// the keychain was last active does not exceed its `inactivity_threshold`; in
/// such a scenario, the removal of keys and reading of passwords will return
/// immediately. This threshold starts off zeroed: by default, these operations
/// *will* require the main password, always.
///
/// ## Security of stored keys
///
/// The password of every key stored in a keychain goes through various security
/// layers, ensuring that no one—except for its keys' keychain—is able to read
/// it, since passing through these layers is unfeasible for modern hardware.
/// There are 4 (four) layers:
///
/// ### Main-password hashing
///
/// The main password of the keychain is hashed upon instantiation, using the
/// Argon2i function; given a random **16-byte (128-bit) salt**,
/// **2 iterations** are performed, resulting in a **16-byte (128-bit) hash**.
///
/// Argon2 is a *memory-hard function*: it consumes as much memory as possible
/// when hashing, preventing attackers from cracking passwords with rainbow
/// table or dictionary attacks, in which attempts to guess the main password
/// would be made by feeding the keychain with precomputed or known passwords
/// gathered from data breaches. Because these attackers may take advantage of
/// specialized hardware (e.g., FPGAs), the aforementioned salt is insufficient
/// by itself. Therefore, in Key6, *at most* **64 MiB** will be consumed.
///
/// (When a keychain is instantiated, its main password undergoes some
/// verifications as to keep the keychain minimally secure. For more on these,
/// refer to `MainPassword.validate()`.)
///
/// ## Locking
///
/// As discussed, the keychain remains unlocked for the amount of milliseconds
/// in `inactivity_threshold` since the last unlock, with such value zeroed by
/// default for maximum security. Despite this threshold, the keychain will
/// *always* request that its main password be provided when storing a key.
/// Besides preventing an unauthorized user from changing the keychain, doing so
/// allows for deriving a passphrase in the next layer from the main password
/// (rather than from its hash, already known by the keychain).
///
/// Similarly, reading the password of a key, i.e., calling `readPassword()`,
/// will require an unlock when this keychain is inactive.
///
/// ## Passphrase derivation
///
/// The first step of the process of encrypting the password of a key is
/// generating a master key with the PBKDF2 hash function from the main
/// password. As to not confuse such *master* key with *keychain* keys, the term
/// "passphrase" is adopted.
///
/// The passphrase is *never* stored in the heap; rather, it always gets derived
/// again each time some key is stored in the keychain or the password of a
/// stored key is read.
///
/// ## Passphrase encryption/decryption
///
/// Upon storing a key in the keychain, the passphrase derived in the previous
/// step is passed into the AES-256-GCM cipher as the AES key. The encryption,
/// with a 12-byte (96-bit) initialization vector (IV) and a 16-byte (128-bit)
/// tag, outputs a 32-byte (256-bit) ciphertext.
///
/// ## References
///
/// - Schlawack, H. (2015). *Choosing Parameters*. std.crypto.pwhash.argon2-cffi 25.1.0
///   documentation.
///   https://std.crypto.pwhash.argon2-cffi.readthedocs.io/en/stable/parameters.html;
/// - A. Biryukov, D. Dinu & D. Khovratovich. (2016). *Argon2: New Generation of
///   Memory-Hard Functions for Password Hashing and Other Applications*. 2016
///   IEEE European Symposium on Security and Privacy (EuroS&P), Saarbruecken,
///   Germany, pp. 292-302;
/// - Turan, M.S., Barker, E.B., Burr, W.E., & Chen, L. (2010). *Recommendation
///   for Password-Based Key Derivation; Part 1: Storage Applications*; and
/// - 1Password. (2026, March 5). *1Password Security Design White Paper*.
///   https://agilebits.github.io/security-design.
pub const Keychain = struct {
    /// Maximum amount of attempts to enter the main password. Once incorrect
    /// passwords have been provided more times than the quantity assigned to
    /// this field, an error will be returned by the function of this keychain
    /// that tried to unlock it.
    max_unlock_attempt_count: usize,

    /// Duration in seconds since the last unlock from which an unlock will be
    /// required again for reading the credentials of keys and removing keys
    /// stored in this keychain.
    inactivity_threshold_in_secs: u128,

    allocator: std.mem.Allocator,
    csprng: std.Random.DefaultCsprng,
    main_password_hash: []const u8,
    main_password_verify_options: std.crypto.pwhash.argon2.VerifyOptions,
    current_unlock_attempt_count: usize,
    last_activity_timestamp_in_secs: u128,
    store: std.AutoHashMap(u128, Key),

    /// Failure resulted from attempting to perform an operation related
    /// strictly to a keychain.
    pub const Error = error{
        /// The amount of unsuccessful attempts to unlock the keychain was
        /// greater than the maximum quantity defined for that specific keychain.
        TooManyUnlockAttempts,

        /// The keychain was attempted to be unlocked without its main password
        /// while the keychain was locked.
        Locked,
    };

    /// Entry specific to a given keychain, consisting of user metadata
    /// regarding authentication at a specific site.
    pub const Key = struct {
        /// Identifier of this key, unique in the keychain in which this key is
        /// stored.
        id: u128,

        /// Arbitrary, user-defined string used for distinguishing one key from
        /// another from the user's point of view. This doesn't have to be
        /// unique, as the _truly_ unique identifier of a key is its `id`.
        label: []const u8,

        /// Identifier of the user at the site. Usually, consists of an e-mail,
        /// a username or a phone number.
        login: []const u8,

        /// Ciphertext from having encrypted the password in plaintext of this
        /// key.
        credential: ?Credential,

        /// URI that leads to the site. Usually, is that of a local file or a
        /// website.
        path: ?std.Uri,

        /// Encrypted password for authenticating at a site.
        pub const Credential = struct {
            /// 256-bit sequence generated randomly by a CSPRNG, used to encrypt
            /// the password.
            key: [key_len]u8,

            /// Random bytes for producing different ciphertexts when encrypting
            /// two equal paswords. This is an input for encryption and,
            /// afterward, decryption.
            iv: [iv_len]u8,

            /// Bytes generated after encryption of the password, with which the
            /// encrypted password can be decrypted and ensured that no external
            /// attacker tampered with it.
            authentication_tag: [authentication_tag_len]u8,

            /// Encrypted contents of this credential.
            ciphertext: []const u8,

            const associated_data = "";
            const key_len = std.crypto.aead.aes_gcm.Aes256Gcm.key_length;
            const iv_len = std.crypto.aead.aes_gcm.Aes256Gcm.nonce_length;
            const authentication_tag_len =
                std.crypto.aead.aes_gcm.Aes256Gcm.tag_length;

            fn decrypt(
                self: Credential,
                allocator: std.mem.Allocator,
            ) ![]const u8 {
                const password = try allocator.alloc(u8, self.ciphertext.len);
                try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
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
                iv: [iv_len]u8,
            ) error{OutOfMemory}!Credential {
                var key: [key_len]u8 = undefined;
                csprng.fill(&key);
                const ciphertext = try allocator.alloc(u8, password.len);
                var authentication_tag: [authentication_tag_len]u8 = undefined;
                std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
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
        /// returned when *retrieving* a key, but may happen when storing one,
        /// due to the arbitrarity of the user-provided arguments.
        pub const Error = error{
            /// The key's ID isn't a UUID v7. With v7 UUIDs, apart from them
            /// being sufficiently unique, we can sort keys based on the time at
            /// which they were stored in the keychain.
            MalformedID,

            /// The key's label was left blank. An unlabeled key would be
            /// confusing and significantly difficult to distinguish from other
            /// keys, given that its ID isn't user-facing (and, event if it was,
            /// doesn't give some human-readable clue about *which* key it
            /// identifies).
            Unlabeled,

            /// The key contains neither login nor password. It is required that
            /// one of the two isn't blank, since the purpose of a key is to
            /// store *some* authentication information.
            Insufficient,
        };

        /// Represents a "level" in which a key has been given information in
        /// order for such key to be sufficient. In case none of the three
        /// levels are that of the key and it gets validated by `validate()`
        /// afterward, an error will be returned.
        pub const Sufficiency = enum {
            /// A non-blank login and a blank password were provided to the key.
            contains_login_only,

            /// A blank login and a non-blank password were provided to the key.
            contains_credential_only,

            /// A non-blank login and a non-blank password were provided to the
            /// key.
            contains_login_and_credential,
        };

        const zuid = @import("zuid");

        pub fn _init(
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
            var iv: [Credential.iv_len]u8 = undefined;
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
        
        pub fn _validate(self: Key) @This().Error!void {
            try validateID(self.id);
            try validateLabel(self.label);
            const credential_ciphertext =
                if (self.credential) |credential| credential.ciphertext else "";
            _ = try validateSufficiency(self.login, credential_ciphertext);
        }

        pub fn _deinit(self: Key, allocator: std.mem.Allocator) void {
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
            return if (is_login_blank and strings.isBlank(password))
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
            /// The main password contains either no characters whatsoever or
            /// only spaces.
            Blank,

            /// The main password contains characters repeated consecutively
            /// more than 4 times. Using such a password would impact the
            /// security of the keychain negatively by making brute-force
            /// attacks easier.
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
            params: std.crypto.pwhash.argon2.Params,
        ) std.crypto.pwhash.Error![]const u8 {
            var out: [128]u8 = undefined;
            const options = std.crypto.pwhash.argon2.HashOptions{
                .allocator = allocator,
                .params = params,
            };
            return std.crypto.pwhash.argon2.strHash(
                main_password,
                options,
                &out,
                io,
            );
        }
    };
 
    pub const c = @import("keychain.c.zig");
    pub const tests = @import("keychain.tests.zig");

    /// Maximum amount of consecutive characters in the main password of a
    /// keychain.
    pub const max_main_password_consecution_len = 4;

    const strings = @import("utils/strings.zig");

    /// Initializes a keychain with the given main password given in plaintext.
    /// A hash of such password is calculated through Argon2, and used to
    /// encrypt the keys stored in the keychain.
    ///
    /// The main password is constrained to some rules regarding its contents,
    /// given that bypassing these rules would result in an insecure keychain. A
    /// balance between convenience and security is tried to be maintained. The
    /// rules are:
    ///
    /// 1. There MUST be at least 1 character.
    /// 2. There MUST be at least 1 non-space character.
    /// 3. There MUST NOT be more than 4 consecutive repetitions of the same
    ///    character.
    ///
    /// Apart from following these rules, the caller of this initializer is
    /// responsible for discarding the given password afterward.
    ///
    /// The passed-in RNG is not that of the keychain itself; rather, its only
    /// role in this initialization is to generate the seed for the keychain's
    /// CSPRNG.
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        rng: std.Random,
        main_password: []const u8,
        main_password_hasher_params: std.crypto.pwhash.argon2.Params,
    ) !Keychain {
        var csprng_seed: [std.Random.DefaultCsprng.secret_seed_length]u8 =
            undefined;
        rng.bytes(&csprng_seed);
        try MainPassword.validate(main_password);
        return .{
            .max_unlock_attempt_count = 3,
            .inactivity_threshold_in_secs = 0,
            .allocator = allocator,
            .csprng = .init(csprng_seed),
            .main_password_hash = try MainPassword.hash(
                allocator,
                io,
                main_password,
                main_password_hasher_params,
            ),
            .main_password_verify_options = .{ .allocator = allocator },
            .current_unlock_attempt_count = 0,
            .last_activity_timestamp_in_secs = 0,
            .store = .init(allocator),
        };
    }

    /// Encrypts and stores the credentials for a given site, alongside
    /// additional user-facing information such as a label and a path. All
    /// posterior reads to sensitive data will require that this keychain be
    /// unlocked, and may prompt the user to provide this keychain's main
    /// password.
    pub fn storeKey(
        self: *Keychain,
        io: std.Io,
        label: []const u8,
        login: []const u8,
        plain_password: []const u8,
        path: ?std.Uri,
    ) !Key {
        const key = try Key._init(
            self.allocator,
            io,
            &self.csprng,
            label,
            login,
            plain_password,
            path,
        );
        try self.store.put(key.id, key);
        return key;
    }

    /// Reads non-sensitive information about a key with the given ID that's
    /// been stored in this keychain. As the credentials of such key are still
    /// encrypted even when it's returned, this operation doesn't require that
    /// this keychain be unlocked.
    ///
    /// This function will error in case the ID is malformed, or return null if
    /// it isn't that of a key stored in this keychain.
    pub fn findKey(self: Keychain, id: u128) Key.Error!?Key {
        try Key.validateID(id);
        return self.store.get(id);
    }

    /// Decrypts the credential of the given key. This function requires both
    /// that this keychain be unlocked and such key belong to this keychain;
    /// otherwise, an error or null is returned, respectively.
    pub fn readPassword(self: Keychain, io: std.Io, key: Key) !?[]const u8 {
        if (self.isLocked(nowInSecs(io)))
            return Error.Locked;
        if (!self.store.contains(key.id))
            return null;
        if (key.credential) |credential|
            return try credential.decrypt(self.allocator);
        return null;
    }

    /// Allows for reading the credentials of keys from now on, until the
    /// duration defined as the inactivity threshold of this keychain. After
    /// such time, attempting to read those credentials without having called
    /// this function again will result in an error being thrown.
    ///
    /// This function is a no-op in case this keychain is already unlocked _and_
    /// no main password (i.e., a null one) is passed in.
    pub fn unlock(
        self: *Keychain,
        io: std.Io,
        main_password: ?[]const u8,
    ) Error!void {
        const now_in_secs = nowInSecs(io);
        const mp = main_password orelse
            return if (!self.isLocked(now_in_secs)) {} else Error.Locked;
        std.crypto.pwhash.argon2.strVerify(
            self.main_password_hash,
            mp,
            self.main_password_verify_options,
            io,
        ) catch |err| switch (err) {
            std.crypto.errors.Error.InvalidEncoding,
            std.crypto.errors.Error.PasswordVerificationFailed,
            => {
                if (self.current_unlock_attempt_count ==
                    self.max_unlock_attempt_count)
                {
                    self.current_unlock_attempt_count = 0;
                    return Error.TooManyUnlockAttempts;
                }
                self.current_unlock_attempt_count += 1;
                return;
            },
            else => {},
        };
        self.current_unlock_attempt_count = 0;
        self.last_activity_timestamp_in_secs = now_in_secs;
    }

    /// Frees memory allocated by this keychain.
    pub fn deinit(self: *Keychain) void {
        var key_iter = self.store.valueIterator();
        while (key_iter.next()) |key|
            key._deinit(self.allocator);
        self.store.deinit();
    }

    fn isLocked(self: Keychain, now_in_secs: u128) bool {
        return now_in_secs -
            self.last_activity_timestamp_in_secs >
            self.inactivity_threshold_in_secs;
    }

    fn nowInSecs(io: std.Io) u128 {
        return @intCast(std.Io.Clock.real.now(io).toSeconds());
    }
};

const std = @import("std");

test {
    std.testing.refAllDecls(Keychain);
}
