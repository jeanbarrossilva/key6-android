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
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Actor responsible for the main feature of Key6: storing, hashing and
 * retrieving authentication information of the user at various sites. Besides
 * securing these data, allows for generating random passwords with custom
 * constraints and, consequently, providing greater safety against attacks
 * targeting these sites.
 *
 * Sites are referred to throughout this entire documentation. Sites are any
 * files or services accessible via a login and/or a password. Despite their
 * name, they are not limited to *web*sites; they can also be, e.g., a
 * compressed file requiring a password.
 *
 * Keys, on the other hand, are the combination of these information for
 * authentication at a specific site. When they are stored in a keychain, a
 * unique identifier is generated for them automatically, and returned as a
 * string. As it is an implementation detail and subject to change, no
 * assumptions on the format of this string should be made; however, as of v1.0
 * of Key6, every key identifier is a UUID v7.
 */
@OptIn(ExperimentalUuidApi::class)
class Keychain {
  private val store = HashMap<String, Key>()

  /**
   * Authentication metadata for a site.
   *
   * @property id Unique identifier of this key in the keychain into which it is
   *   stored.
   * @property title Display identifier of this key. This may not be unique, as
   *   it serves only for the user to distinguish one key from another;
   *   internally, rather, keys are identified by their [id].
   * @property login Primary identification of the user at the site; usually
   *   their e-mail address or username. May be blank, as sites may not demand
   *   one while still enforcing a password.
   * @property password Private string defined by the user as the pair to their
   *   login (if set) for authenticating at the site. If the login has been
   *   specified, this may be blank.
   * @property uri Address of the site at which the user signed up with the
   *   given login and password. This may refer to a website, a local file
   *   (e.g., a password-protected compressed file), etc.
   */
  @ConsistentCopyVisibility
  data class Key
  internal constructor(
    val id: String,
    val title: String,
    val login: String,
    val password: String,
    val uri: URI?
  )

  /**
   * Exception that may be thrown when storing a key into a keychain.
   *
   * @param message Description of why this error occurred.
   */
  sealed class KeyStoreError(message: String) :
    IllegalArgumentException(message) {
    /** Thrown if a key without a title is requested to be stored. */
    class Untitled internal constructor() :
      KeyStoreError("Key cannot be untitled.")

    /** Thrown when storing a key without either a login or a password. */
    class Insufficient internal constructor() :
      KeyStoreError(
        "A key is required to have one of the two: a login or a password.")
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
   * @param password Private string defined by the user as the pair to their
   *   login (if set) for authenticating at the site. If the login has been
   *   specified, this may be blank.
   * @param uri Address of the site at which the user signed up with the given
   *   login and password. This may refer to a website, a local file (e.g., a
   *   password-protected compressed file), etc.
   */
  @Throws(KeyStoreError::class)
  fun store(title: String, login: String, password: String, uri: URI?): String {
    // Hot take (🙂‍↔️): these verifications should be in the constructor of the
    // 'Key' class rather than here. Works for now, but this will change when
    // other storage mechanisms are introduced.
    if (title.isBlank()) throw KeyStoreError.Untitled()
    if (login.isBlank() && password.isBlank())
      throw KeyStoreError.Insufficient()

    val id = Uuid.generateV7().toString()
    val key = Key(id, title, login, password, uri)
    store[id] = key
    return id
  }

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
}
