/*
 * Copyright © Jean Silva
 *
 * This file is part of the Key6 open-source project.
 *
 * Key6 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * Key6 is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses.
 */

package com.jeanbarrossilva.key6.keychain

import com.jeanbarrossilva.key6.keychain.key.Key
import com.jeanbarrossilva.key6.keychain.key.PlainPassword
import com.jeanbarrossilva.key6.keychain.key.discard
import de.xformerfhs.securesecretkeyspec.crypto.SecureSecretKeySpec
import java.net.URI
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Actor responsible for the main feature of Key6: storing, encrypting and
 * retrieving authentication information of the user at various sites locally.
 * Besides securing these data, allows for generating random passwords with
 * custom constraints and, consequently, providing greater safety against
 * attacks targeting these sites.
 *
 * Sites are referred to throughout this entire documentation. Sites are files
 * or services accessible via a login and/or a password. Despite their name,
 * they are not limited to *web*sites; they can also be, e.g., a compressed file
 * requiring a password.
 *
 * Keys, on the other hand, are the combination of these information for
 * authentication at a specific site. When they are stored in a keychain, a
 * unique identifier is generated for them automatically, and returned as a
 * string. As it is an implementation detail and subject to change, no
 * assumptions on the format of this string should be made; however, as of v1 of
 * Key6, every key identifier is a UUID v7.
 *
 * ## Creating a keychain
 *
 * Instantiating an implementation of [Keychain] may require the main password;
 * furthermore, that keychain might specify that such password be discarded
 * after passed into it, to prevent cross-process reads. Refer to such
 * keychain's documentation and be sure to take the recommended measures.
 *
 * ## Locking and unlocking
 *
 * The sole purpose of a keychain is to make the task of storing passwords and
 * generating strong, new ones easier, removing the burden of having to remember
 * them all from the user. Password-wise, with the process of generating
 * passwords automated, the user's prominence to cyberattacks may be
 * significantly reduced.
 *
 * To achieve this goal, keychains require a single, main password. This
 * password is the only one the user needs to remember, and will be used to
 * unlock the keychain and read passwords stored in it. The keychain *may*
 * require an unlock when
 *
 * 1. reading the password of one of its keys; and
 * 2. removing one of its keys.
 *
 * The main password of the keychain *may* be requested, with a leniency of
 * [maxUnlockAttemptCount] attempts for the correct password to be provided; in
 * case that maximum is exceeded, with all requests having resulted in incorrect
 * passwords, an exception will be thrown, preventing the operation from being
 * performed.
 *
 * The main password *will not* be requested, however, if the time passed since
 * the keychain was last active does not exceed its [inactivityThreshold]; in
 * such a scenario, the removal of keys and reading of passwords will return
 * immediately. This threshold starts off zeroed: by default, these operations
 * *will* require the main password, always.
 *
 * ## Security of stored keys
 *
 * The password of every key stored in a keychain goes through various security
 * layers, ensuring that no one—except for its keys' keychain—is able to read
 * it, since passing through these layers is unfeasible for modern hardware.
 * There are 4 (four) layers:
 *
 * ### Main-password hashing
 *
 * The main password of the keychain is hashed upon instantiation, using the
 * Argon2i function; given a random **16-byte (128-bit) salt**, **2 iterations**
 * are performed, resulting in a **16-byte (128-bit) hash**.
 *
 * Argon2 is a *memory-hard function*: it consumes as much memory as possible
 * when hashing, preventing attackers from cracking passwords with rainbow table
 * or dictionary attacks, in which attempts to guess the main password would be
 * made by feeding the keychain with precomputed or known passwords gathered
 * from data breaches. Because these attackers may take advantage of specialized
 * hardware (e.g., FPGAs), the aforementioned salt is insufficient by itself.
 * Therefore, in Key6, *at most* **64 MiB** will be consumed.
 *
 * (When a keychain is instantiated, its main password undergoes some
 * verifications as to keep the keychain minimally secure. For more on these,
 * refer to [validateMainPassword].)
 *
 * ## Locking
 *
 * As discussed, the keychain remains unlocked for the amount of milliseconds in
 * [inactivityThreshold] since the last unlock, with such value zeroed by
 * default for maximum security. Despite this threshold, the keychain will
 * *always* request that its main password be provided when storing a key.
 * Besides preventing an unauthorized user from changing the keychain, doing so
 * allows for deriving a passphrase in the next layer from the main password
 * (rather than from its hash, already known by the keychain).
 *
 * Similarly, reading the password of a key, i.e., calling
 * [unlockAndGetPassword], will require an unlock when this keychain is
 * inactive.
 *
 * ## Passphrase derivation
 *
 * The first step of the process of encrypting the password of a key is
 * generating a master key with the PBKDF2 hash function from the main password.
 * As to not confuse such *master* key with *keychain* keys, the term
 * "passphrase" is adopted.
 *
 * 2²¹ = 2,097,152 iterations are performed, an amount significantly greater
 * than that of other password managers (such as 1Password, which, as of their
 * 0.5.2 release, iterates "only" 650,000 times).
 *
 * The passphrase is *never* stored in the heap; rather, it always gets derived
 * again each time some key is stored in the keychain or the password of a
 * stored key is read.
 *
 * ## Passphrase encryption/decryption
 *
 * Upon storing a key in the keychain, the passphrase derived in the previous
 * step is passed into the AES-256-GCM cipher as the AES key. The encryption,
 * with a 12-byte (96-bit) initialization vector (IV) and a 16-byte (128-bit)
 * tag, outputs a 32-byte (256-bit) ciphertext.
 *
 * ## References
 *
 * - Schlawack, H. (2015). *Choosing Parameters*. argon2-cffi 25.1.0
 *   documentation.
 *   https://argon2-cffi.readthedocs.io/en/stable/parameters.html;
 * - A. Biryukov, D. Dinu & D. Khovratovich. (2016). *Argon2: New Generation of
 *   Memory-Hard Functions for Password Hashing and Other Applications*. 2016
 *   IEEE European Symposium on Security and Privacy (EuroS&P), Saarbruecken,
 *   Germany, pp. 292-302;
 * - Turan, M.S., Barker, E.B., Burr, W.E., & Chen, L. (2010). *Recommendation
 *   for Password-Based Key Derivation; Part 1: Storage Applications*; and
 * - 1Password. (2026, March 5). *1Password Security Design White Paper*.
 *   https://agilebits.github.io/security-design.
 *
 * @see generatePlainPassword
 * @see unlockAndRemove
 * @see unlockAndGetPassword
 */
@OptIn(ExperimentalUuidApi::class)
abstract class Keychain {
  /**
   * Whether this keychain has not been unlocked in the last *n* milliseconds,
   * where *n* is the amount of milliseconds in the [inactivityThreshold].
   *
   * When this is `true`, it is guaranteed that the next removal of a key or
   * reading of its password *will*, first, require that the main password be
   * provided in plaintext. Otherwise, these operations will be performed
   * without any restriction.
   *
   * @see unlockAndRemove
   * @see unlockAndGetPassword
   */
  val isLocked
    get() =
      inactivityThresholdInMilliseconds == 0L ||
        System.currentTimeMillis() - lastActivityTimeInMilliseconds >=
          inactivityThresholdInMilliseconds

  /**
   * Amount of time required to have passed since the last time in which this
   * keychain was active for it to be considered idle and, therefore, be locked.
   * Starts off zeroed, but may be changed by the user later.
   *
   * This is guaranteed to be ≥ [Duration.ZERO], where being zeroed denotes that
   * the main password will be requested at each removal of keys or reading of
   * their password. Trying to define it as some negative duration will result
   * in an exception being thrown.
   *
   * @see isLocked
   * @see unlockAndRemove
   * @see unlockAndGetPassword
   */
  var inactivityThreshold
    get() =
      if (inactivityThresholdInMilliseconds == 0L) Duration.ZERO
      else inactivityThresholdInMilliseconds.milliseconds
    @Throws(IllegalArgumentException::class)
    set(inactivityThreshold) {
      require(inactivityThreshold >= Duration.ZERO) {
        "The inactivity threshold of a keychain should be >= 0."
      }
      inactivityThresholdInMilliseconds =
        inactivityThreshold.inWholeMilliseconds
    }

  /**
   * Maximum, positive amount of times an incorrect main password may be
   * provided when trying to unlock this keychain. Upon requesting an operation
   * that requires an unlock (e.g., reading the password of a key) and failing
   * more than the amount defined here, an exception will be thrown.
   *
   * @see unlockAndGetPassword
   */
  var maxUnlockAttemptCount = 3
    set(maxUnlockAttemptCount) {
      require(maxUnlockAttemptCount > 0) {
        "Main password should be allowed to be provided at least 1 (one) time."
      }
      field = maxUnlockAttemptCount
    }

  /** Argon2i hasher for the main password given in plaintext. */
  private val mainPasswordHasher: Argon2iHasher

  /**
   * Non-blocking, cryptographically-secure pseudorandom number generator
   * (CSPRNG) of all salts and IVs of keys stored in this keychain.
   *
   * ## On blocking vs non-blocking CSPRNGs
   *
   * Often, whether `/dev/urandom` should be preferred over `/dev/random` in
   * Unix-like systems is debated. The first does not wait for entropy to
   * increase; rather, it returns a random number immediately. Meanwhile, the
   * second does block the thread until enough environmental noise is gathered.
   * With this explanation on its own, it would seem that the first one is the
   * better, i.e., more secure approach, and that the second results in a "less"
   * random number.
   *
   * However, consider that the "pseudo" in "pseudorandom number generator"
   * means that it is "computationally random"; and that this, in turn, denotes
   * not that numbers *will* be random (as those of a *truly* random number
   * generator), but that they will be *unpredictable*: attempting to guess the
   * next one beforehand is unfeasible for modern-day computers.
   *
   * Besides, ciphers themselves are cracked more often than pseudorandom
   * numbers are guessed; and if the cipher has a vulnerability, whether that
   * number is predictable or not becomes redundant.
   *
   * ## References
   *
   * - Almaraz Luengo, E., & Román Villaizán, J. (2023). *Cryptographically
   *   Secured Pseudo-Random Number Generators: Analysis and Testing with NIST
   *   Statistical Test Suite*. Mathematics, 11(23), 4812.
   *   https://doi.org/10.3390/math11234812; and
   * - Huehn, T. (2014, March 7). *Myths about /dev/urandom*. Thomas Huehn.
   *   https://www.thomas-huehn.com/myths-about-urandom.
   */
  private val csprng: SecureRandom =
    try {
      SecureRandom.getInstance("NativePRNGNonBlocking")
    } catch (_: NoSuchAlgorithmException) {
      SecureRandom()
    }

  /**
   * Amount of milliseconds required to have passed since the last time in which
   * this keychain was active for it to be considered idle and, therefore, be
   * locked. Starts off as zero, but may be changed by the user later.
   *
   * This is guaranteed to be ≥ 0, where being 0 denotes that the main password
   * will be requested at each removal of keys or reading of their password.
   *
   * @see isLocked
   */
  private var inactivityThresholdInMilliseconds = 0L

  /**
   * Time since the Unix epoch, in milliseconds, in which an operation (such as
   * removing a key or reading its password) was last performed by this
   * keychain. By default, represents the time in which the system was when this
   * keychain was instantiated.
   */
  private var lastActivityTimeInMilliseconds = System.currentTimeMillis()

  /**
   * Exception that may be thrown when storing a key in a keychain.
   *
   * @param message Description of why this exception was thrown.
   */
  sealed class StorageException(message: String) :
    IllegalArgumentException(message) {

    /** Thrown if a key without a title is tried to be instantiated. */
    class Untitled internal constructor() :
      StorageException("Key cannot be untitled.")

    /** Thrown when instantiating a key without both a login and a password. */
    class Insufficient internal constructor() :
      StorageException(
        "A key is required to have one of the two: a login or a password.")
  }

  /**
   * Exception thrown whenever a keychain, in an attempt to be unlocked,
   * requests its main password in plaintext [Keychain.maxUnlockAttemptCount]
   * consecutive times and the correct password is never provided.
   *
   * @see Keychain.requestMainPassword
   */
  class IncorrectMainPasswordException internal constructor() :
    IllegalArgumentException("Main password is incorrect.")

  /**
   * Instantiates a keychain from a main password.
   *
   * @param mainPassword Single password for accessing every key stored into the
   *   instantiated keychain, in plaintext. This password **must** be discarded
   *   after the call to this constructor in order to prevent cross-process
   *   accesses to its contents.
   * @see PlainPassword.discard
   */
  @Throws(KeychainException::class)
  protected constructor(mainPassword: PlainPassword) {
    validateMainPassword(mainPassword)
    mainPasswordHasher = Argon2iHasher(csprng)
    mainPasswordHasher.hash(mainPassword)
  }

  /**
   * Generates a random password in plaintext for a key to be stored in this
   * keychain. Secures the user against dictionary attacks and, proportionally
   * to the chosen length, reduces the practicality of rainbow table attacks.
   *
   * @param letters Determines which letters can be included in the password, if
   *   any.
   * @param allowsDigits Whether the password is allowed to contain numbers.
   * @param allowsSymbols Whether non-alphanumeric characters are allowed to be
   *   in the password.
   * @param length Amount of random characters in the generated password.
   * @return The generated plain password. Will be empty if the [length] was
   *   either negative or zero; otherwise, will contain at most
   *   [MAX_GENERATED_PLAIN_PASSWORD_LENGTH] characters.
   */
  fun generatePlainPassword(
    letters: PlainPassword.Letters,
    allowsDigits: Boolean,
    allowsSymbols: Boolean,
    length: Int
  ) =
    PlainPassword.generate(
      csprng,
      letters,
      allowsDigits,
      allowsSymbols,
      min(length, MAX_GENERATED_PLAIN_PASSWORD_LENGTH))

  /**
   * Stores a key into this keychain.
   *
   * @param title [Key.title].
   * @param login [Key.login].
   * @param password Private string defined by the user as the pair to their
   *   login (if set) for authenticating at the site, in plaintext. If the login
   *   has been specified, this may be blank.
   *
   *   This password **must** be discarded after used.
   *
   * @param path [Key.path].
   * @return The identifier generated for the stored key.
   * @see PlainPassword.discard
   */
  @Throws(
    IncorrectMainPasswordException::class,
    StorageException::class,
    RuntimeException::class)
  suspend fun unlockAndStore(
    title: String,
    login: String,
    password: PlainPassword,
    path: URI?
  ): String {
    val (normalizedTitle, normalizedLogin) =
      Key.validateAndNormalize(title, login)
    if (normalizedLogin.isEmpty() && password.isBlank())
      throw StorageException.Insufficient()
    val id = Uuid.generateV7().toString()
    val salt = Key.newZeroedSalt()
    csprng.nextBytes(salt)
    val derivedPassphrase = unlockAndDerivePassphrase(salt)
    val iv = Key.newZeroedIV()
    csprng.nextBytes(iv)
    val encryptedPassword = encryptPassword(password, iv, derivedPassphrase)
    derivedPassphrase.discard()
    val key =
      Key(
        id, normalizedTitle, normalizedLogin, salt, iv, encryptedPassword, path)
    store(key)
    return key.id
  }

  /**
   * Obtains the password of the specified key, undoing the encryption performed
   * on it when it was stored.
   *
   * @param keyID ID of the key whose password will be obtained.
   * @return The decrypted password, or null if the key is not stored in this
   *   keychain.
   */
  suspend fun unlockAndGetPassword(keyID: String): PlainPassword? {
    val key = get(keyID) ?: return null
    return unlockAndDecryptPassword(key)
  }

  /**
   * Retrieves a key previously stored into this keychain.
   *
   * @param keyID Unique identifier of the key to be retrieved.
   * @return The stored key, or null if no key with the given ID is stored at
   *   the moment.
   * @see unlockAndStore
   */
  abstract suspend operator fun get(keyID: String): Key?

  /**
   * Removes a key stored into this keychain. In case there is no key with the
   * given ID, calling this method is a no-op.
   *
   * @param keyID Unique identifier of the key to be removed.
   */
  suspend fun unlockAndRemove(keyID: String) {
    if (isLocked) unlockAndDiscardMainPassword()
    remove(keyID)
  }

  /**
   * Adds the given key to this keychain, making it retrievable afterward.
   *
   * @param key Key to be stored.
   * @see get
   */
  protected abstract suspend fun store(key: Key)

  /**
   * Removes the key with the given ID from this keychain.
   *
   * @param keyID Unique identifier of the key to be removed.
   */
  protected abstract suspend fun remove(keyID: String)

  /**
   * Requests that the main password of this keychain be provided in plaintext.
   * This callback is called whenever a key is requested and this keychain has
   * been idle for longer than its inactivity threshold.
   *
   * @return The provided main password in plaintext. May be different from the
   *   actual one of this keychain, since there might be a typo or the user may
   *   not be the owner of this keychain.
   *
   *   This password **must** be discarded after used, since the GC may not be
   *   deterministic and, thus, the password may outlive the scope of the
   *   caller, potentially exposing it to other processes.
   *
   * @see PlainPassword.discard
   */
  protected abstract suspend fun requestMainPassword(): PlainPassword

  /**
   * Last step of the encryption of the plain password of a key, in which the
   * AES-256-GCM algorithm encrypts the passphrase derived from the main
   * password. Rather than the key's plain password, this is what is stored in a
   * key, alongside the salt for the [derivedPassphrase] and the [iv].
   *
   * @param password The password for the key to be stored, in plaintext.
   * @param iv 12-byte (96-bit) array generated randomly by the [csprng].
   * @param derivedPassphrase A passphrase returned by
   *   [unlockAndDerivePassphrase].
   * @return The given password, AES-256-GCM-encrypted.
   */
  private fun encryptPassword(
    password: PlainPassword,
    iv: ByteArray,
    derivedPassphrase: ByteArray
  ): ByteArray {
    val cipher = Cipher.getInstance(CIPHER_NAME)
    val keySpec = SecretKeySpec(derivedPassphrase, "AES")
    val modeSpec = GCMParameterSpec(CIPHER_TAG_LENGTH_IN_BITS, iv)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, modeSpec)
    val encryptedPassword = cipher.doFinal(password.encode())
    return encryptedPassword
  }

  /**
   * Undoes the AES-256-GCM encryption performed on the password of the given
   * key, re-deriving the passphrase from this keychain's main password.
   *
   * @param key Key whose password will be decrypted. Implied to belong to this
   *   keychain (i.e., to *be* or *have been* stored in it), since the
   *   encryption process involved deriving from its keychain's main password.
   */
  private suspend fun unlockAndDecryptPassword(key: Key): PlainPassword {
    val derivedPassphrase = unlockAndDerivePassphrase(key.salt)
    val cipher: Cipher = Cipher.getInstance(CIPHER_NAME)
    val keySpec = SecureSecretKeySpec(derivedPassphrase, "AES")
    val modeSpec = GCMParameterSpec(CIPHER_TAG_LENGTH_IN_BITS, key.iv)
    cipher.init(Cipher.DECRYPT_MODE, keySpec, modeSpec)
    val encodedPasswordContents: ByteArray =
      cipher.doFinal(key.encryptedPassword)
    derivedPassphrase.discard()
    keySpec.destroy()
    return PlainPassword.decodeAndMove(encodedPasswordContents)
  }

  /**
   * First step of a key's password encryption, in which this keychain's main
   * password is hashed using PBKDF2, deriving a passphrase from it to be passed
   * into the AES-256-GCM cipher.
   *
   * @param salt 16-byte (128-bit) array whose bytes are random, generated by
   *   the [csprng].
   * @return The PBKDF2-derived passphrase.
   *
   * Note that, because garbage collection (GC) in the JVM *may not* be
   * deterministic, the caller exiting scope **does not** guarantee that this
   * passphrase will be discarded; therefore, this passphrase **must** be
   * discarded after used.
   *
   * @see requestMainPassword
   * @see ByteArray.fill
   */

  // We derive from the main password; there may be a potential for improvement
  // here. 1Password, for example, generates their Secret Key on device, from
  // which their equivalent of our passphrase is derived.
  //
  // https://agilebits.github.io/security-design/deepKeys.html#combining-with-the-secret-key
  @Throws(IncorrectMainPasswordException::class)
  private suspend fun unlockAndDerivePassphrase(salt: ByteArray): ByteArray {
    val mainPassword = unlockAndKeepMainPassword()
    val mainPasswordAsArray = mainPassword.asCharArray()
    val sizeInBits = 256
    val spec =
      PBEKeySpec(
        mainPasswordAsArray, salt, /* iterationCount= */ 1 shl 21, sizeInBits)

    // The main password and the array obtained from it are discarded because
    // JVM's GC may not be deterministic; this way, they will remain
    // inaccessible by someone able to read the array.
    //
    // 'spec' is not affected by this, given that it makes a copy of it.
    mainPassword.discard()
    mainPasswordAsArray.discard()

    val passphrase =
      SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        .generateSecret(spec)
        .encoded

    // Same reasoning as above here. Now that we've already derived the
    // passphrase, we clear that copy of the main password that 'spec' made,
    // preventing the aforementioned unwanted accesses.
    spec.clearPassword()

    return passphrase
  }

  /**
   * Alias for calling [unlockAndKeepMainPassword] and discarding the given
   * password immediately afterward. For when an operation requires unlocking
   * the keychain, but the password itself is irrelevant.
   *
   * @see PlainPassword.discard
   */
  @Throws(IncorrectMainPasswordException::class)
  private suspend fun unlockAndDiscardMainPassword() =
    unlockAndKeepMainPassword().discard()

  /**
   * Requests that this keychain be unlocked (if locked) by having its main
   * password provided in plaintext. Essential for operations that require
   * maximum security, such as obtaining the password of some key.
   *
   * Up to [maxUnlockAttemptCount] attempts of providing the correct main
   * password may be made. In case the user fails at that, this method will
   * throw an exception and prohibit the operation from being performed.
   *
   * @return The provided, correct main password.
   *
   *   **Must** be discarded after used, since JVM's GC may not be deterministic
   *   and, thus, allow for this password to live longer than the caller scope,
   *   potentially making it readable by other processes. In cases in which the
   *   given password would *not* be used, [unlockAndDiscardMainPassword] should
   *   be called instead.
   *
   * @see requestMainPassword
   * @see unlockAndGetPassword
   * @see PlainPassword.discard
   */
  @Throws(IncorrectMainPasswordException::class)
  private suspend fun unlockAndKeepMainPassword(): PlainPassword {
    var requestedMainPassword: PlainPassword
    var unlockAttemptCount = 0
    while (true) {
      requestedMainPassword = requestMainPassword()
      if (mainPasswordHasher.isMatch(requestedMainPassword)) break
      else if (unlockAttemptCount < maxUnlockAttemptCount) unlockAttemptCount++
      else throw IncorrectMainPasswordException()
    }
    markAsActive()
    return requestedMainPassword
  }

  /**
   * Marks this keychain as currently being in an active state, updating its
   * last activity time to that of the system since the Unix epoch. This is
   * essential for automatically locking this keychain when the amount of time
   * since its last activity (defined by the user) has been exceeded.
   */
  private fun markAsActive() {
    lastActivityTimeInMilliseconds = System.currentTimeMillis()
  }

  companion object {
    /**
     * Maximum amount of characters in a plain password generated by a keychain.
     *
     * @see Keychain.generatePlainPassword
     */
    const val MAX_GENERATED_PLAIN_PASSWORD_LENGTH = 128

    /**
     * Name of the AES-GCM cipher for encrypting/decrypting a key's password.
     */
    private const val CIPHER_NAME: String = "AES/GCM/NoPadding"

    /**
     * Amount of bytes in the authentication tag in the AES-258-GCM cipher for
     * encrypting/decrypting keys' passwords.
     */
    private const val CIPHER_TAG_LENGTH_IN_BITS = 128

    /**
     * Ensures that the main password given when instantiating some type of
     * keychain is minimally secure. There are some rules that a main password
     * should follow. It
     *
     * 1. must be, at least, 8 (eight) characters long; and
     * 2. most of its characters cannot be whitespaces.
     *
     * If one of these rules is violated, this method will throw a
     * [KeychainException] respective to that rule.
     *
     * @param mainPassword Main password in plaintext to be validated.
     */
    @JvmStatic
    @Throws(KeychainException::class)
    fun validateMainPassword(mainPassword: PlainPassword) {
      val areMostCharactersWhitespaces = {
        mainPassword.findConsecutions(Char::isWhitespace).any {
          it.count >= mainPassword.length / 2
        }
      }
      if (mainPassword.length < 8 || areMostCharactersWhitespaces())
        throw KeychainException.ShortMainPassword()
    }
  }
}

/**
 * Exception that may be thrown when instantiating a keychain.
 *
 * @param message Description of why this exception was thrown.
 */
sealed class KeychainException(message: String) :
  IllegalArgumentException(message) {
  /**
   * Thrown if a keychain is attempted to be instantiated with a main password
   * with less than 8 characters; or in case it is mostly filled with
   * whitespaces.
   */
  class ShortMainPassword internal constructor() :
    KeychainException(
      "Main password of a keychain should contain at least 8 characters.")
}
