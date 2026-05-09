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

import assertk.all
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
  @Test
  fun throwsIfStoringUntitledKey() {
    val keychain = Keychain()
    assertFailure {
        keychain.store(
          title = "",
          login = "john@appleseed.com",
          password = "123",
          uri = null)
      }
      .isInstanceOf<Keychain.KeyStoreError.Untitled>()
  }

  @Parameters(", ", " ,")
  @Test
  fun throwsIfStoringKeyNoLoginAndNoPassword(login: String, password: String) {
    val keychain = Keychain()
    assertFailure {
        keychain.store(title = "Lorem ipsum", login, password, uri = null)
      }
      .isInstanceOf<Keychain.KeyStoreError.Insufficient>()
  }

  @Test
  fun storesKey() {
    val keychain = Keychain()
    val login = "john@appleseed.com"
    val password = "123"
    val uri = URI.create("https://website.com/")
    val keyID = keychain.store(title = "Lorem ipsum", login, password, uri)
    assertThat(keychain)
      .transform("get") { it[keyID] }
      .isNotNull()
      .all {
        prop(Keychain.Key::id).isEqualTo(keyID)
        prop(Keychain.Key::login).isEqualTo(login)
        prop(Keychain.Key::password).isEqualTo(password)
        prop(Keychain.Key::uri).isEqualTo(uri)
      }
  }

  @Parameters("", " ")
  @Test
  fun storesKeyWithLoginAndNoPassword(password: String) {
    val keychain = Keychain()
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        password,
        uri = null)
    assertThat(keychain)
      .transform("get") { it[keyID] }
      .isNotNull()
      .prop(Keychain.Key::id)
      .isEqualTo(keyID)
  }

  @Test
  fun removesKey() {
    val keychain = Keychain()
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        password = "123",
        uri = null)
    keychain.remove(keyID)
    assertThat(keychain).transform("get") { it[keyID] }.isNull()
  }
}
