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
import com.jeanbarrossilva.key6.keychain.key.Key
import com.jeanbarrossilva.key6.keychain.key.PlainPassword
import com.jeanbarrossilva.key6.keychain.key.test.asUnsafePlainPassword
import com.jeanbarrossilva.key6.keychain.key.test.generate
import java.net.URI
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
        FakeKeychain.withMainPassword(mainPassword.asUnsafePlainPassword())
      }
    }

    @Test
    fun throwsIfInstantiatingWithMainPasswordWithLessThanEightCharacters() {
      assertFailure {
        FakeKeychain.withMainPassword(
          PlainPassword.move(charArrayOf('1', '2', '3', '4', '5', '6', '7')))
      }
    }

    @Test
    fun throwsIfInstantiatingWithMainPasswordWithMostlyWhitespaces() {
      assertFailure {
        FakeKeychain.withMainPassword("1   2".asUnsafePlainPassword())
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
              PlainPassword.generate(),
              path = null)
          }
          .isInstanceOf<Keychain.StorageException.Untitled>()
      }
    }

    @Parameters("LOWEST,, ", "LOWEST, ,", "MID,, ", "MID, ,")
    @Test
    fun throwsIfStoringKeyNoLoginAndNoPassword(
      unlockAttemptRate: UnlockAttemptRate,
      keyLogin: String,
      keyPassword: String
    ) {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(unlockAttemptRate)
      runTest {
        assertFailure {
            keychain.unlockAndStore(
              title = "Lorem ipsum",
              keyLogin,
              keyPassword.asUnsafePlainPassword(),
              path = null)
          }
          .isInstanceOf<Keychain.StorageException.Insufficient>()
      }
    }

    @Parameters("LOWEST", "MID")
    @Test
    fun storesKey(unlockAttemptRate: UnlockAttemptRate) {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(unlockAttemptRate)
      val keyTitle = "Lorem ipsum"
      val keyLogin = "john@appleseed.com"
      val keyDecodedPassword = PlainPassword.generate()
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
            prop(Key::id).isEqualTo(keyID)
            prop(Key::title).isEqualTo(keyTitle)
            prop(Key::login).isEqualTo(keyLogin)
            prop(Key::encryptedPassword).isNotIn(keyEncodedPassword)
            prop(Key::path).isEqualTo(keyPath)
          }
      }
    }

    @Parameters("LOWEST,", "LOWEST, ", "MID,", "MID, ")
    @Test
    fun storesKeyWithLoginAndNoPassword(
      unlockAttemptRate: UnlockAttemptRate,
      keyPassword: String
    ) {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(unlockAttemptRate)
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            keyPassword.asUnsafePlainPassword(),
            path = null)
        assertThat(keychain)
          .transform("get($keyID)") { it[keyID] }
          .isNotNull()
          .prop(Key::id)
          .isEqualTo(keyID)
      }
    }

    @Test
    fun storedKeyPasswordIsEncrypted() {
      val keychain = FakeKeychain.withRandomMainPassword()
      val keyPassword = PlainPassword.generate()
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
          .prop(Key::encryptedPassword)
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
          .suspendCall("unlockAndGetPassword($nonStoredKeyID)") {
            it.unlockAndGetPassword(nonStoredKeyID)
          }
          .isNull()
      }
    }

    @Test
    fun decryptsStoredKeyPassword() {
      val keychain = FakeKeychain.withRandomMainPassword()
      val keyPassword = PlainPassword.generate()
      runTest {
        val keyID =
          keychain.unlockAndStore(
            title = "Lorem ipsum",
            login = "john@appleseed.com",
            keyPassword,
            path = null)
        assertThat(keychain)
          .suspendCall("unlockAndGetPassword($keyID)") {
            it.unlockAndGetPassword(keyID)
          }
          .isEqualTo(keyPassword)
      }
    }
  }

  class LockTests {
    @Test
    fun isLockedByDefault() {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(UnlockAttemptRate.LOWEST)
      assertThat(keychain).all {
        prop(FakeKeychain::isLocked).isTrue()
        prop(FakeKeychain::inactivityThreshold).isEqualTo(Duration.ZERO)
      }
    }

    @Test
    fun throwsIfInactivityThresholdIsNegative() {
      val keychain = FakeKeychain.withRandomMainPassword()
      keychain.setUnlockAttemptRate(UnlockAttemptRate.LOWEST)
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
            PlainPassword.generate(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.EXCEEDING)
        assertThat(keychain)
          .transform("get($keyID)") { it[keyID] }
          .isNotNull()
          .prop(Key::id)
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
            PlainPassword.generate(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.EXCEEDING)
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
            PlainPassword.generate(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.EXCEEDING)
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
            PlainPassword.generate(),
            path = null)
        keychain.setUnlockAttemptRate(UnlockAttemptRate.EXCEEDING)
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
          PlainPassword.generate(),
          path = null)
      keychain.unlockAndRemove(keyID)
      assertThat(keychain).transform("get($keyID)") { it[keyID] }.isNull()
    }
  }
}
