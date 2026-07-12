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

package com.jeanbarrossilva.key6.keychain.key

import com.jeanbarrossilva.key6.keychain.Keychain.StorageException
import java.net.URI
import java.util.Objects
import java.util.UUID

/**
 * Authentication metadata for a site.
 *
 * @property id Identifier of this key, unique in the keychain in which it is
 *   stored.
 * @property title Trimmed display identifier of this key. This may not be
 *   unique, as it serves only for the user to distinguish one key from another;
 *   internally, rather, keys are identified by their [id].
 * @property login Trimmed primary identification of the user at the site;
 *   usually their e-mail address or username. May be empty, as sites may not
 *   demand one while still enforcing a password.
 * @property salt Random 16-byte (128-bit) array generated for deriving the
 *   encrypted password of this key via PBKDF2. Prevents other keys with the
 *   same password from having the same encrypted password.
 * @property iv 12-byte (96-bit) initialization vector passed into the AES-GCM
 *   cipher alongside this key's encrypted password.
 * @property encryptedPassword Encrypted form of the private string defined by
 *   the user as the pair to their login (if set) for authenticating at the
 *   site. If the login has been specified, this may be empty.
 * @property path Path to the site at which the user signed up with the given
 *   login and password. This may refer to a website, a local file (e.g., a
 *   password-protected compressed file), etc.
 */
class Key
internal constructor(
  val id: String,
  val title: String,
  val login: String,
  val salt: ByteArray,
  val iv: ByteArray,
  val encryptedPassword: ByteArray,
  val path: URI?
) {
  override fun equals(other: Any?) =
    other is Key &&
      id == other.id &&
      title == other.title &&
      login == other.login &&
      salt.contentEquals(other.salt) &&
      iv.contentEquals(other.iv) &&
      encryptedPassword.contentEquals(other.encryptedPassword) &&
      path == other.path

  override fun hashCode() =
    Objects.hash(id, title, login, salt, iv, encryptedPassword, path)

  companion object {
    /**
     * Instantiates a zeroed, 16-byte array to be populated with random bytes
     * and serve as the salt of a key.
     */
    @JvmStatic fun newZeroedSalt() = ByteArray(size = 16)

    /**
     * Instantiates a zeroed, 12-byte array to be populated with random bytes
     * and serve as the IV of a key.
     */
    @JvmStatic fun newZeroedIV() = ByteArray(size = 12)

    /**
     * Attempts to instantiate a key.
     *
     * @param id [Key.id].
     * @param title [Key.title].
     * @param login [Key.login].
     * @param salt [Key.salt].
     * @param iv [Key.iv].
     * @param encryptedPassword [Key.encryptedPassword].
     * @param path [Key.path].
     * @see newZeroedSalt
     * @see newZeroedIV
     */
    @JvmStatic
    @Throws(KeyException::class, StorageException::class)
    fun new(
      id: String,
      title: String,
      login: String,
      salt: ByteArray,
      iv: ByteArray,
      encryptedPassword: ByteArray,
      path: URI?
    ): Key {
      val trimmedID = id.trim()
      if (trimmedID.isEmpty()) throw KeyException.NonUuidV7ID(version = null)
      val uuidVersion =
        try {
          UUID.fromString(trimmedID).version()
        } catch (_: IllegalArgumentException) {
          null
        }
      if (uuidVersion != 7) throw KeyException.NonUuidV7ID(uuidVersion)
      val (normalizedTitle, normalizedLogin) =
        validateAndNormalize(title, login)
      if (salt.size != 16) throw KeyException.Non16ByteSalt(salt.size)
      if (iv.size != 12) throw KeyException.Non12ByteIV(iv.size)
      return Key(
        id, normalizedTitle, normalizedLogin, salt, iv, encryptedPassword, path)
    }

    /**
     * Ensures that a key can be instantiated with the given title and login,
     * throwing an exception in case the title is blank and would, thus, result
     * in an invalid key.
     *
     * @param title [Key.title] to validate.
     * @param login [Key.login] to validate.
     * @return The title and the login, trimmed.
     */
    @JvmStatic
    @Throws(StorageException.Untitled::class)
    internal fun validateAndNormalize(title: String, login: String) =
      title.trim().ifEmpty { throw StorageException.Untitled() } to login.trim()
  }
}

/**
 * Exception for when a key is attempted to be instantiated with an argument in
 * an invalid format.
 *
 * @param message Description of why this exception was thrown.
 * @see Key.new
 */
sealed class KeyException(message: String) : IllegalArgumentException(message) {
  /**
   * Thrown if the given ID is not a UUID v7.
   *
   * @param version Version of the UUID, or null in case the ID was not a UUID.
   */
  class NonUuidV7ID internal constructor(val version: Int?) :
    KeyException(
      "ID of a key should be a UUID v7" +
        (version?.let { "(was $it)" } ?: "") +
        ".")

  /**
   * Thrown if the salt is not an array with 16 bytes.
   *
   * @param size Amount of bytes in the given salt.
   */
  class Non16ByteSalt internal constructor(val size: Int) :
    KeyException("Salt of a key should contain 16 bytes (got $size).")

  /**
   * Thrown if the IV is not an array with 12 bytes.
   *
   * @param size Amount of bytes in the given IV.
   */
  class Non12ByteIV internal constructor(val size: Int) :
    KeyException("IV of a key should contain 12 bytes (got $size).")
}
