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

import java.net.URI
import java.util.Objects
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Actor responsible for the main feature of Key6: storing, hashing and
 * retrieving authentication information of the user at various sites. Besides
 * securing these data, allows for generating random passwords with custom
 * constraints and, consequently, providing greater safety against attacks
 * targeting these sites.
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
 * Keychains of different types may differ in how they hash their passwords. It
 * is recommended to use a keychain that applies any variant of the Argon2 hash
 * function in production because, despite the disadvantage in performance, such
 * a function consumes a significant amount of memory, difficulting the
 * unhashing of its passwords. Keychains with less secure functions may be used
 * for testing for the sake of performance.
 *
 * All types of keychain expose a factory method for instantiating them from a
 * main password in plaintext: `T.Companion.withPlainMainPassword(String)`,
 * where `T` is the type.
 *
 * When a type of keychain is requested to be instantiated (i.e., its factory
 * method is called), the given plain main password undergoes some verifications
 * as to keep the keychain minimally secure. For more on these, refer to
 * [validatePlainMainPassword].
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
 * unlock the keychain and unhash passwords stored into it. The keychain *may*
 * require an unlock when
 *
 * - reading one of its keys; and
 * - removing one of its keys.
 *
 * The main password of the keychain *may* be requested, with a leniency of
 * [maxUnlockAttemptCount] attempts for the correct password to be provided; in
 * case that maximum is exceeded, with all requests having resulted in incorrect
 * passwords, an exception will be thrown, preventing the operation from being
 * performed.
 *
 * The main password *will not* be requested, however, if the time passed since
 * the keychain was last active does not exceed its [inactivityThreshold]; in
 * such a scenario, the reading and removal of keys will return immediately.
 * This threshold starts off zeroed: by default, these operations *will* require
 * the main password, always.
 */
@OptIn(ExperimentalUuidApi::class)
abstract class Keychain {
  /**
   * Whether this keychain has not been unlocked in the last *n* milliseconds,
   * where *n* is the amount of milliseconds in the [inactivityThreshold].
   *
   * When this is `true`, it is guaranteed that the next reading or removal of a
   * key *will*, first, require that the main password be provided in plaintext.
   * Otherwise, these operations will be performed without any restriction.
   *
   * @see get
   * @see remove
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
   * the main password will be requested at each reading or removal of keys.
   * Trying to define it as some negative duration will result in an exception
   * being thrown.
   *
   * @see isLocked
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
   * Maximum amount of times an incorrect main password may be provided when
   * trying to unlock this keychain. Upon requesting an operation that requires
   * an unlock (e.g., obtaining a key) and failing more than the amount defined
   * here, an exception will be thrown.
   */
  var maxUnlockAttemptCount = 3

  /**
   * Hashed form of the single password for accessing every key stored into this
   * keychain.
   */
  protected val hashedMainPassword: String

  /**
   * Keys stored into this keychain by a prior call to [store], and that have
   * not yet been removed. The string to which each of them is associated is
   * their identifier, allowing for O(1) retrievals through calls to [get].
   */
  private val storage = HashMap<String, Key>()

  /**
   * Amount of milliseconds required to have passed since the last time in which
   * this keychain was active for it to be considered idle and, therefore, be
   * locked. Starts off as zero, but may be changed by the user later.
   *
   * This is guaranteed to be ≥ 0, where being 0 denotes that the main password
   * will be requested at each reading or removal of keys.
   *
   * @see isLocked
   */
  private var inactivityThresholdInMilliseconds = 0L

  /**
   * Unix epoch in which an operation (such as reading or removing a key) was
   * last performed by this keychain. By default, represents the time in which
   * the system was when this keychain was instantiated.
   */
  private var lastActivityTimeInMilliseconds = System.currentTimeMillis()

  /** Authentication metadata for a site. */
  class Key {
    /**
     * Unique identifier of this key in the keychain into which it is stored.
     */
    val id: String

    /**
     * Display identifier of this key. This may not be unique, as it serves only
     * for the user to distinguish one key from another; internally, rather,
     * keys are identified by their [id].
     */
    val title: String

    /**
     * Primary identification of the user at the site; usually their e-mail
     * address or username. May be empty, as sites may not demand one while
     * still enforcing a password.
     */
    val login: String

    /**
     * Path to the site at which the user signed up with the given login and
     * password. This may refer to a website, a local file (e.g., a
     * password-protected compressed file), etc.
     */
    val path: URI?

    /**
     * Hashed form of the private string defined by the user as the pair to
     * their login (if set) for authenticating at the site. If the login has
     * been specified, this may be empty.
     */
    internal val hashedPassword: String

    @Throws(KeyException::class)
    internal constructor(
      id: String,
      title: String,
      login: String,
      hashedPassword: String,
      path: URI?
    ) {
      this.title = title.trim()
      this.login = login.trim()
      if (this.title.isEmpty()) throw KeyException.Untitled()
      if (this.login.isEmpty() && hashedPassword.isBlank())
        throw KeyException.Insufficient()
      this.hashedPassword = hashedPassword
      this.id = id
      this.path = path
    }

    override fun equals(other: Any?) =
      other is Key &&
        id == other.id &&
        title == other.title &&
        login == other.login &&
        hashedPassword == other.hashedPassword &&
        path == other.path

    override fun hashCode() =
      Objects.hash(id, title, login, hashedPassword, path)
  }

  /**
   * Exception that may be thrown when instantiating a key.
   *
   * @param message Description of why this exception was thrown.
   */
  sealed class KeyException(message: String) :
    IllegalArgumentException(message) {
    /** Thrown if a key without a title is tried to be instantiated. */
    class Untitled internal constructor() :
      KeyException("Key cannot be untitled.")

    /** Thrown when instantiating a key without both a login and a password. */
    class Insufficient internal constructor() :
      KeyException(
        "A key is required to have one of the two: a login or a password.")
  }

  /**
   * Exception thrown whenever a keychain, in an attempt to be unlocked,
   * requests its main password in plaintext [Keychain.maxUnlockAttemptCount]
   * consecutive times and the correct password is never provided.
   *
   * @see Keychain.requestPlainMainPassword
   */
  class IncorrectMainPasswordException internal constructor() :
    IllegalArgumentException("Main password is incorrect.")

  /**
   * Instantiates a keychain from a plain main password.
   *
   * @param plainMainPassword Single password for accessing every key stored
   *   into the instantiated keychain, in plaintext.
   */
  @Throws(KeychainException::class)
  protected constructor(plainMainPassword: String) {
    validatePlainMainPassword(plainMainPassword)
    hashedMainPassword = hash(plainMainPassword)
  }

  /**
   * Stores a key into this keychain.
   *
   * @param title Display identifier of the key. This may not be unique, as it
   *   serves only for the user to distinguish one key from another; internally,
   *   rather, keys are identified by their identifier.
   * @param login Primary identification of the user at the site; usually their
   *   e-mail address or username. May be blank, as sites may not demand one
   *   while still enforcing a password.
   * @param plainPassword Private string defined by the user as the pair to
   *   their login (if set) for authenticating at the site, in plaintext. If the
   *   login has been specified, this may be blank.
   * @param path Path to the site at which the user signed up with the given
   *   login and password. This may refer to a website, a local file (e.g., a
   *   password-protected compressed file), etc.
   * @return The identifier generated for the stored key.
   */
  @Throws(KeyException::class, RuntimeException::class)
  fun store(
    title: String,
    login: String,
    plainPassword: String,
    path: URI?
  ): String {
    val id = Uuid.generateV7().toString()
    val hashedPassword = hash(plainPassword)
    storage[id] = Key(id, title, login, hashedPassword, path)
    return id
  }

  /**
   * Requests that the main password of this keychain be provided in plaintext.
   * This callback is called whenever a key is requested and this keychain has
   * been idle for longer than its inactivity threshold.
   *
   * @return The provided main password in plaintext. May be different from the
   *   actual one of this keychain, since there might be a typo or the user may
   *   not be the owner of this keychain.
   */
  protected abstract suspend fun requestPlainMainPassword(): String

  /**
   * Hashes the plain password of a key being stored, using the algorithm
   * specific to this implementation.
   *
   * @param plainPassword Some password in plaintext. This may be the main
   *   password of this keychain, or the password of a key that will be stored
   *   into it.
   */
  protected abstract fun hash(plainPassword: String): String

  /**
   * Undoes the hashing performed by a previous call to [hash] on the given
   * password. By definition, for some password *x* in plaintext,
   *
   * - `hash(x)` = [hashedPassword]; and
   * - `unhash(hashedPassword)` = *x*.
   *
   * @param hashedPassword Password hashed by this keychain. This may be the
   *   hashed form of the main password of this keychain, or that of the
   *   password of a key stored into it.
   */
  protected abstract fun unhash(hashedPassword: String): String

  /**
   * Retrieves a key previously stored into this keychain.
   *
   * @param keyID Unique identifier of the key to be retrieved.
   * @return The stored key, or `null` if no key with the given ID is stored at
   *   the moment.
   */
  @Throws(IncorrectMainPasswordException::class)
  suspend operator fun get(keyID: String): Key? {
    unlock()
    return storage[keyID]
  }

  /**
   * Removes a key stored into this keychain. In case there is no key with the
   * given ID, calling this method is a no-op.
   *
   * @param keyID Unique identifier of the key to be removed.
   */
  suspend fun remove(keyID: String) {
    unlock()
    storage.remove(keyID)
  }

  /**
   * Requests that this keychain be unlocked (if locked) by having its main
   * password provided in plaintext. Essential for operations that require
   * maximum security, such as reading some key.
   *
   * Up to [maxUnlockAttemptCount] attempts of providing the correct main
   * password may be made. In case the user fails at that, this method will
   * throw an exception and prohibit the operation from being performed.
   */
  @Throws(IncorrectMainPasswordException::class)
  private suspend fun unlock() {
    if (!isLocked) return
    var unlockAttemptCount = 0
    val expectedPlainMainPassword = unhash(hashedMainPassword)
    while (true) {
      val providedPlainMainPassword = requestPlainMainPassword()
      if (providedPlainMainPassword == expectedPlainMainPassword) break
      else if (unlockAttemptCount < maxUnlockAttemptCount) unlockAttemptCount++
      else throw IncorrectMainPasswordException()
    }
    markAsActive()
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
     * Ensures that the plain main password given when instantiating some type
     * of keychain is minimally secure. There are some rules that a plain main
     * password should follow. It
     *
     * 1. must be, at least, 8 (eight) characters long; and
     * 2. most of its characters cannot be whitespaces.
     *
     * If one of these rules is violated, this method will throw a
     * [KeychainException] respective to that rule.
     *
     * @param plainMainPassword Main password in plaintext to be validated.
     */
    @JvmStatic
    @Throws(KeychainException::class)
    private fun validatePlainMainPassword(plainMainPassword: String) {
      val areMostCharactersWhitespaces = {
        plainMainPassword.findConsecutions(Char::isWhitespace).any {
          it.count >= plainMainPassword.length / 2
        }
      }
      if (plainMainPassword.length < 8 || areMostCharactersWhitespaces())
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
  class ShortMainPassword :
    KeychainException(
      "Plain main password of a keychain should contain at least 8 characters.")
}
