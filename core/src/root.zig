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
/// - Schlawack, H. (2015). *Choosing Parameters*. argon2-cffi 25.1.0
///   documentation.
///   https://argon2-cffi.readthedocs.io/en/stable/parameters.html;
/// - A. Biryukov, D. Dinu & D. Khovratovich. (2016). *Argon2: New Generation of
///   Memory-Hard Functions for Password Hashing and Other Applications*. 2016
///   IEEE European Symposium on Security and Privacy (EuroS&P), Saarbruecken,
///   Germany, pp. 292-302;
/// - Turan, M.S., Barker, E.B., Burr, W.E., & Chen, L. (2010). *Recommendation
///   for Password-Based Key Derivation; Part 1: Storage Applications*; and
/// - 1Password. (2026, March 5). *1Password Security Design White Paper*.
///   https://agilebits.github.io/security-design.
pub const Keychain = @import("Keychain.zig");

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
