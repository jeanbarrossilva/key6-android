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
import assertk.assertions.hasLength
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotEqualTo
import assertk.assertions.isNotIn
import assertk.assertions.isNotNull
import assertk.assertions.isNull
import assertk.assertions.isTrue
import assertk.assertions.prop
import assertk.coroutines.assertions.suspendCall
import com.jeanbarrossilva.key6.keychain.test.newRandomWithDirectBuffer
import java.net.URI
import java.nio.CharBuffer
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Suite

@RunWith(Suite::class)
@Suite.SuiteClasses(
  KeychainTests.InstantiationTests::class,
  KeychainTests.KeyStorageTests::class,
  KeychainTests.KeyDecryptionTests::class,
  KeychainTests.LockTests::class,
  KeychainTests.PlainPasswordGenerationTests::class)
internal class KeychainTests {
  @RunWith(JUnitParamsRunner::class)
  class InstantiationTests {
    /*
     * Although we're using a specific keychain implementation here, because all
     * factory methods end up calling the super constructor (by which
     * verifications on the plain main password are done), the instantiation
     * behavior remains the same throughout implementations.
     */

    @Parameters("", " ")
    @Test
    fun throwsIfInstantiatingWithBlankMainPassword(mainPassword: String) {
      assertFailure {
        FakeKeychain.withMainPassword(
          PlainPassword(CharBuffer.wrap(mainPassword))
        )
      }
    }

    @Test
    fun throwsIfInstantiatingWithMainPasswordWithLessThanEightCharacters() {
      assertFailure {
        FakeKeychain.withMainPassword(PlainPassword(CharBuffer.wrap("1234567")))
      }
    }

    @Test
    fun throwsIfInstantiatingWithMainPasswordWithMostlyWhitespaces() {
      assertFailure {
        FakeKeychain.withMainPassword(PlainPassword(CharBuffer.wrap("1   2")))
      }
    }
  }

  @RunWith(JUnitParamsRunner::class)
  class KeyStorageTests {
    @Test
    fun throwsIfStoringUntitledKey() {
      val keychain = FakeKeychain.withRandomMainPassword()
      runTest {
        assertFailure {
            keychain.unlockAndStore(
              title = "",
              login = "john@appleseed.com",
              PlainPassword.newRandomWithDirectBuffer(),
              path = null)
          }
          .isInstanceOf<Keychain.StorageException.Untitled>()
      }
    }

    @Parameters("Lowest,, ", "Lowest, ,", "Mid,, ", "Mid, ,")
    @Test
    fun throwsIfStoringKeyNoLoginAndNoPassword(
      unlockAttemptRate: UnlockAttemptRate,
      login: String,
      password: String
    ) {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(unlockAttemptRate)
      runTest {
        assertFailure {
            keychain.unlockAndStore(
              title = "Lorem ipsum",
              login,
              PlainPassword(CharBuffer.wrap(password)),
              path = null)
          }
          .isInstanceOf<Keychain.StorageException.Insufficient>()
      }
    }

    @Parameters("Lowest", "Mid")
    @Test
    fun storesKey(unlockAttemptRate: UnlockAttemptRate) {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(unlockAttemptRate)
      val keyTitle = "Lorem ipsum"
      val keyLogin = "john@appleseed.com"
      val keyDecodedPassword = PlainPassword.newRandomWithDirectBuffer()
      val keyEncodedPassword = keyDecodedPassword.encode()
      val keyPath = URI.create("https://website.com/")
      runTest {
        val keyID =
          keychain.unlockAndStore(
            keyTitle, keyLogin, keyDecodedPassword, keyPath)
        assertThat(keychain)
          .transform("get($keyID)") { it[keyID] }
          .isNotNull()
          .all {
            prop(Keychain.Key::id).isEqualTo(keyID)
            prop(Keychain.Key::title).isEqualTo(keyTitle)
            prop(Keychain.Key::login).isEqualTo(keyLogin)
            prop(Keychain.Key::encryptedPassword).isNotIn(keyEncodedPassword)
            prop(Keychain.Key::path).isEqualTo(keyPath)
          }
      }
    }

    @Parameters("Lowest,", "Lowest, ", "Mid,", "Mid, ")
    @Test
    fun storesKeyWithLoginAndNoPassword(
      unlockAttemptRate: UnlockAttemptRate,
      password: String
    ) {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(unlockAttemptRate)
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            PlainPassword(CharBuffer.wrap(password)),
            path = null)
        assertThat(keychain)
          .transform("get($keyID)") { it[keyID] }
          .isNotNull()
          .prop(Keychain.Key::id)
          .isEqualTo(keyID)
      }
    }

    @Test
    fun storedKeyPasswordIsEncrypted() {
      val keychain = FakeKeychain.withRandomMainPassword()
      val keyPassword = PlainPassword.newRandomWithDirectBuffer()
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            keyPassword,
            path = null)
        assertThat(keychain)
          .transform("get($keyID)") { it[keyID] }
          .isNotNull()
          .prop(Keychain.Key::encryptedPassword)
          .isNotEqualTo(keyPassword)
      }
    }
  }

  class KeyDecryptionTests {
    @Test
    fun returnsNullForPasswordOfUnstoredKey() {
      val keychain = FakeKeychain.withRandomMainPassword()

      @OptIn(ExperimentalUuidApi::class)
      val nonStoredKeyID = Uuid.generateV7().toString()

      runTest {
        assertThat(keychain)
          .suspendCall("getPassword($nonStoredKeyID)") {
            it.unlockAndGetPassword(nonStoredKeyID)
          }
          .isNull()
      }
    }

    @Test
    fun decryptsStoredKeyPassword() {
      val keychain = FakeKeychain.withRandomMainPassword()
      val keyPassword = PlainPassword.newRandomWithDirectBuffer()
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            keyPassword,
            path = null)
        assertThat(keychain)
          .suspendCall("getPassword($keyID)") { it.unlockAndGetPassword(keyID) }
          .isEqualTo(keyPassword)
      }
    }
  }

  class LockTests {
    @Test
    fun isLockedByDefault() {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(UnlockAttemptRate.Lowest)
      assertThat(keychain).all {
        prop(FakeKeychain::isLocked).isTrue()
        prop(FakeKeychain::inactivityThreshold).isEqualTo(Duration.ZERO)
      }
    }

    @Test
    fun throwsIfInactivityThresholdIsNegative() {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(UnlockAttemptRate.Lowest)
      assertFailure { keychain.inactivityThreshold = (-2).milliseconds }
        .isInstanceOf<IllegalArgumentException>()
    }

    @Test
    fun readsKeyWithoutUnlockingWhenInactivityThresholdIsNotExceeded() {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.inactivityThreshold = Duration.INFINITE
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            PlainPassword.newRandomWithDirectBuffer(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.Exceeding)
        assertThat(keychain)
          .transform("get($keyID)") { it[keyID] }
          .isNotNull()
          .prop(Keychain.Key::id)
          .isEqualTo(keyID)
      }
    }

    @Test
    fun throwsIfCannotUnlockToReadKeyPassword() {
      val keychain = FakeKeychain.withRandomMainPassword()
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            PlainPassword.newRandomWithDirectBuffer(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.Exceeding)
        assertFailure { keychain.unlockAndGetPassword(keyID) }
          .isInstanceOf<Keychain.IncorrectMainPasswordException>()
      }
    }

    @Test
    fun throwsIfCannotUnlockToRemoveKey() {
      val keychain = FakeKeychain.withRandomMainPassword()
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            PlainPassword.newRandomWithDirectBuffer(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.Exceeding)
        assertFailure { keychain.unlockAndRemove(keyID) }
          .isInstanceOf<Keychain.IncorrectMainPasswordException>()
      }
    }

    @Test
    fun removesKeyWithoutUnlockingWhenInactivityThresholdIsNotExceeded() {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.inactivityThreshold = Duration.INFINITE
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            PlainPassword.newRandomWithDirectBuffer(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.Exceeding)
        keychain.unlockAndRemove(keyID)
      }
    }
  }

  @RunWith(JUnitParamsRunner::class)
  class PlainPasswordGenerationTests {
    @Test
    fun truncates() {
      val keychain = FakeKeychain.withRandomMainPassword()
      val generatedPassword =
        keychain.generatePlainPassword(
          PlainPassword.Letters.WITH_DIACRITICS,
          allowsDigits = true,
          allowsSymbols = true,
          length = Keychain.MAX_GENERATED_PLAIN_PASSWORD_LENGTH * 2)
      assertThat(generatedPassword)
        .hasLength(Keychain.MAX_GENERATED_PLAIN_PASSWORD_LENGTH)
    }
  }

  @Test
  fun removesKey() {
    val keychain = FakeKeychain.withRandomMainPassword()
    runTest {
      val keyID =
        keychain.unlockAndStore(
          title = "Lorem ipsum",
          login = "john@appleseed.com",
          PlainPassword.newRandomWithDirectBuffer(),
          path = null)
      keychain.unlockAndRemove(keyID)
      assertThat(keychain).transform("get($keyID)") { it[keyID] }.isNull()
    }
  }
}
