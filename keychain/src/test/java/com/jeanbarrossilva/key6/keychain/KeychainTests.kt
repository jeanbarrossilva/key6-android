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
import assertk.assertions.isTrue
import assertk.assertions.prop
import assertk.coroutines.assertions.suspendCall
import java.net.URI
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Suite

@RunWith(Suite::class)
@Suite.SuiteClasses(
  KeychainInstantiationTests::class,
  KeychainKeyStorageTests::class,
  KeychainLockTests::class)
class KeychainTests {
  @Test
  fun removesKey() {
    val keychain = UnsecureKeychain.withRandomMainPassword()
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        plainPassword = "123",
        path = null)
    runTest {
      keychain.remove(keyID)
      assertThat(keychain).suspendCall("get($keyID)") { it[keyID] }.isNull()
    }
  }
}

@RunWith(JUnitParamsRunner::class)
class KeychainInstantiationTests {
  /*
   * Although we're using a specific keychain implementation here, because all
   * factory methods end up calling the super constructor (by which
   * verifications on the plain main password are done), the instantiation
   * behavior remains the same throughout implementations.
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
}

@RunWith(JUnitParamsRunner::class)
class KeychainKeyStorageTests {
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

  @Parameters("Lowest,, ", "Lowest, ,", "Mid,, ", "Mid, ,")
  @Test
  fun throwsIfStoringKeyNoLoginAndNoPassword(
    unlockAttemptRateName: String,
    login: String,
    password: String
  ) {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(
        UnlockAttemptRate.valueOf(unlockAttemptRateName))
    assertFailure {
        keychain.store(title = "Lorem ipsum", login, password, path = null)
      }
      .isInstanceOf<Keychain.KeyException.Insufficient>()
  }

  @Parameters("Lowest", "Mid")
  @Test
  fun storesKey(unlockAttemptRateName: String) {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(
        UnlockAttemptRate.valueOf(unlockAttemptRateName))
    val keyTitle = "Lorem ipsum"
    val keyLogin = "john@appleseed.com"
    val keyPlainPassword = "123"
    val keyHashedPassword = keychain.hash(keyPlainPassword)
    val keyPath = URI.create("https://website.com/")
    val keyID = keychain.store(keyTitle, keyLogin, keyPlainPassword, keyPath)
    runTest {
      assertThat(keychain)
        .suspendCall("get($keyID)") { it[keyID] }
        .isNotNull()
        .isEqualTo(
          Keychain.Key(keyID, keyTitle, keyLogin, keyHashedPassword, keyPath))
    }
  }

  @Parameters("Lowest,", "Lowest, ", "Mid,", "Mid, ")
  @Test
  fun storesKeyWithLoginAndNoPassword(
    unlockAttemptRateName: String,
    password: String
  ) {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(
        UnlockAttemptRate.valueOf(unlockAttemptRateName))
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        password,
        path = null)
    runTest {
      assertThat(keychain)
        .suspendCall("get($keyID)") { it[keyID] }
        .isNotNull()
        .prop(Keychain.Key::id)
        .isEqualTo(keyID)
    }
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
    runTest {
      assertThat(keychain)
        .suspendCall("get($keyID)") { it[keyID] }
        .isNotNull()
        .prop(Keychain.Key::hashedPassword)
        .isEqualTo(keyHashedPassword)
    }
  }
}

class KeychainLockTests {
  @Test
  fun isLockedByDefault() {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(UnlockAttemptRate.Lowest)
    assertThat(keychain).all {
      prop(UnsecureKeychain::isLocked).isTrue()
      prop(UnsecureKeychain::inactivityThreshold).isEqualTo(Duration.ZERO)
    }
  }

  @Test
  fun throwsIfInactivityThresholdIsNegative() {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(UnlockAttemptRate.Lowest)
    assertFailure { keychain.inactivityThreshold = (-2).milliseconds }
      .isInstanceOf<IllegalArgumentException>()
  }

  @Test
  fun throwsIfCannotUnlockToReadKey() {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(UnlockAttemptRate.Exceeding)
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        plainPassword = "123",
        path = null)
    runTest {
      assertFailure { keychain[keyID] }
        .isInstanceOf<Keychain.IncorrectMainPasswordException>()
    }
  }

  @Test
  fun readsKeyWithoutUnlockingWhenInactivityThresholdIsNotExceeded() {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(UnlockAttemptRate.Exceeding)
    keychain.inactivityThreshold = Duration.INFINITE
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        plainPassword = "123",
        path = null)
    runTest {
      assertThat(keychain)
        .suspendCall("get($keyID)") { it[keyID] }
        .isNotNull()
        .prop(Keychain.Key::id)
        .isEqualTo(keyID)
    }
  }

  @Test
  fun throwsIfCannotUnlockToRemoveKey() {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(UnlockAttemptRate.Exceeding)
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        plainPassword = "123",
        path = null)
    runTest {
      assertFailure { keychain.remove(keyID) }
        .isInstanceOf<Keychain.IncorrectMainPasswordException>()
    }
  }

  @Test
  fun removesKeyWithoutUnlockingWhenInactivityThresholdIsNotExceeded() {
    val keychain =
      UnsecureKeychain.withRandomMainPassword(UnlockAttemptRate.Exceeding)
    keychain.inactivityThreshold = Duration.INFINITE
    val keyID =
      keychain.store(
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        plainPassword = "123",
        path = null)
    runTest { keychain.remove(keyID) }
  }
}
