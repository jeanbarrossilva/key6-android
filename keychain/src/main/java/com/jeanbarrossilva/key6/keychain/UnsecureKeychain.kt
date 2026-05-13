/*
 * Copyright © Jean Silva
 *
 * This file is part of the Key6 open-source project.
 *
 * Key6 is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * Key6 is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses.
 */

package com.jeanbarrossilva.key6.keychain

import org.apache.commons.lang3.RandomStringUtils
import kotlin.io.encoding.Base64

/**
 * Keychain for testing purposes only, as it is very, *very* basic. Stored
 * passwords are hashed by being encoded to Base64, which can be easily undone
 * by some perpetrator in production.
 *
 * @param plainMainPassword Single password for accessing every key stored into
 *   the instantiated keychain, in plaintext.
 */
class UnsecureKeychain private constructor(plainMainPassword: String) :
  Keychain(plainMainPassword) {
  public override fun hash(plainPassword: String) =
    Base64.encode(plainPassword.toByteArray())

  companion object {
    /** Instantiates an unsecure keychain with a pseudorandom main password. */
    @JvmStatic
    fun withRandomMainPassword() =
      withPlainMainPassword(RandomStringUtils.insecure().next(8))

    /**
     * Instantiates this type of keychain with its main password specified in
     * plaintext (i.e., unhashed). For security, it will be hashed by the time
     * this function returns, and its plaintext form will become unrecoverable
     * (assuming that such form remains unreferenced after calling this
     * function).
     *
     * @param plainMainPassword Single password for accessing every key stored
     *   into the instantiated keychain, in plaintext.
     */
    @JvmStatic
    @Throws(KeychainException::class)
    fun withPlainMainPassword(plainMainPassword: String) =
      UnsecureKeychain(plainMainPassword)
  }
}
