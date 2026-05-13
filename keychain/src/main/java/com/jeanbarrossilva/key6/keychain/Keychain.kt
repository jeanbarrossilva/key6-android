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
 * ## Main-password mechanism
 *
 * The sole purpose of a keychain is to make the task of storing passwords and
 * generating strong, new ones easier, removing the burden of having to remember
 * them all from the user. Password-wise, with the process of generating
 * passwords automated, the user's prominence to cyberattacks may be
 * significantly reduced.
 *
 * To achieve this goal, keychains require a single, main password; this
 * password is the only one the user needs to remember. It will be used to
 * "unlock" (i.e., unhash) every password stored into the keychain.
 *
 * ## Creating a keychain
 *
 * Keychains of different types differ, only, in how they hash their passwords.
 * It is recommended to use a keychain that applies any variant of the Argon2
 * hash function in production because, despite the disadvantage in performance,
 * such a function consumes a significant amount of memory, difficulting the
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
 */
@OptIn(ExperimentalUuidApi::class)
abstract class Keychain {
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
  private val store = HashMap<String, Key>()

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
     * Hashed form of the private string defined by the user as the pair to
     * their login (if set) for authenticating at the site. If the login has
     * been specified, this may be empty.
     */
    val hashedPassword: String

    /**
     * Path to the site at which the user signed up with the given login and
     * password. This may refer to a website, a local file (e.g., a
     * password-protected compressed file), etc.
     */
    val path: URI?

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
    store[id] = Key(id, title, login, hashedPassword, path)
    return id
  }

  /**
   * Hashes the plain password of a key being stored, using the algorithm
   * specific to this implementation.
   *
   * @param plainPassword Some password in plaintext. This may be the main
   *   password of this keychain, or the password of a key to be stored.
   */
  protected abstract fun hash(plainPassword: String): String

  /**
   * Retrieves a key previously stored into this keychain.
   *
   * @param keyID Unique identifier of the key to be retrieved.
   * @return The stored key, or `null` if no key with the given ID is stored at
   *   the moment.
   */
  operator fun get(keyID: String) = store[keyID]

  /**
   * Removes a key stored into this keychain. In case there is no key with the
   * given ID, calling this method is a no-op.
   *
   * @param keyID Unique identifier of the key to be removed.
   */
  fun remove(keyID: String) {
    store.remove(keyID)
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
