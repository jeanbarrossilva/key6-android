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

import assertk.assertFailure
import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotNull
import assertk.assertions.isNull
import assertk.assertions.prop
import java.net.URI
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(JUnitParamsRunner::class)
class KeychainTests {
  /*
   * 1. On the factory method:
   *    Although we're using a specific keychain implementation here, because
   *    all factory methods end up calling the super constructor (by which
   *    verifications on the plain main password are done), the instantiation
   *    behavior remains the same throughout implementations.
   */

  @Parameters("", " ")
  @Test
  fun throwsIfInstantiatingWithBlankPlainMainPassword(
    plainMainPassword: String
  ) {
    assertFailure { UnsecureKeychain.withPlainMainPassword(plainMainPassword) }
  }

  @Test
  fun throwsIfInstantiatingWithPlainMainPasswordWithLessThanEightCharacters() {
    assertFailure { UnsecureKeychain.withPlainMainPassword("1234567") }
  }

  @Test
  fun throwsIfInstantiatingWithPlainMainPasswordWithMostlyWhitespaces() {
    assertFailure { UnsecureKeychain.withPlainMainPassword("1   2") }
  }

  @Test
  fun throwsIfStoringUntitledKey() {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    assertFailure {
        keychain.store(
          title = "",
          login = "john@appleseed.com",
          plainPassword = "123",
          path = null)
      }
      .isInstanceOf<Keychain.KeyException.Untitled>()
  }

  @Parameters(", ", " ,")
  @Test
  fun throwsIfStoringKeyNoLoginAndNoPassword(login: String, password: String) {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    assertFailure {
        keychain.store(title = "Lorem ipsum", login, password, path = null)
      }
      .isInstanceOf<Keychain.KeyException.Insufficient>()
  }

  @Test
  fun storesKey() {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    val keyTitle = "Lorem ipsum"
    val keyLogin = "john@appleseed.com"
    val keyPlainPassword = "123"
    val keyHashedPassword = keychain.hash(keyPlainPassword)
    val keyPath = URI.create("https://website.com/")
    val keyID = keychain.store(keyTitle, keyLogin, keyPlainPassword, keyPath)
    assertThat(keychain)
      .transform("get($keyID)") { it[keyID] }
      .isNotNull()
      .isEqualTo(
        Keychain.Key(keyID, keyTitle, keyLogin, keyHashedPassword, keyPath))
  }

  @Parameters("", " ")
  @Test
  fun storesKeyWithLoginAndNoPassword(password: String) {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        password,
        path = null)
    assertThat(keychain)
      .transform("get($keyID)") { it[keyID] }
      .isNotNull()
      .prop(Keychain.Key::id)
      .isEqualTo(keyID)
  }

  @Test
  fun storedKeyPasswordIsHashed() {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    val keyPlainPassword = "123"
    val keyHashedPassword = keychain.hash(keyPlainPassword)
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        keyPlainPassword,
        path = null)
    assertThat(keychain)
      .transform("get($keyID)") { it[keyID] }
      .isNotNull()
      .prop(Keychain.Key::hashedPassword)
      .isEqualTo(keyHashedPassword)
  }

  @Test
  fun removesKey() {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        plainPassword = "123",
        path = null)
    keychain.remove(keyID)
    assertThat(keychain).transform("get($keyID)") { it[keyID] }.isNull()
  }
}
