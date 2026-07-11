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

import assertk.all
import assertk.assertFailure
import assertk.assertThat
import assertk.assertions.containsExactly
import assertk.assertions.hasLength
import assertk.assertions.isEmpty
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotEqualTo
import assertk.assertions.isNotSameInstanceAs
import assertk.assertions.isSameInstanceAs
import assertk.assertions.prop
import com.jeanbarrossilva.key6.keychain.key.test.newRandomBackingArray
import com.jeanbarrossilva.key6.keychain.key.test.newRandomWithDirectBuffer
import com.jeanbarrossilva.key6.keychain.key.test.newRandomWithNonDirectBuffer
import com.kevinmost.junit_retry_rule.Retry
import com.kevinmost.junit_retry_rule.RetryRule
import java.nio.CharBuffer
import java.util.Random
import java.util.concurrent.ThreadLocalRandom
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import kotlin.time.Duration.Companion.seconds
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Suite

@RunWith(Suite::class)
@Suite.SuiteClasses(
  PlainPasswordTests.CharArrayConversion::class,
  PlainPasswordTests.CloningTests::class,
  PlainPasswordTests.CodingTests::class,
  PlainPasswordTests.ComparisonTests::class,
  PlainPasswordTests.DiscardingTests::class,
  PlainPasswordTests.GenerationTests::class,
  PlainPasswordTests.TOTPGenerationTests::class)
internal class PlainPasswordTests {
  class CharArrayConversion {
    @Test
    fun asCharArrayReturnsTheEmptyBackingArrayIfThePasswordIsEmpty() =
      assertThat(PlainPassword.newEmpty())
        .prop(PlainPassword::asCharArray)
        .all {
          isEmpty()
          isSameInstanceAs(PlainPassword.newEmpty().asCharArray())
        }

    @Test
    fun asCharArrayReturnsTheBackingArrayIfThePasswordHasOne() {
      val backingArray = PlainPassword.newRandomBackingArray()
      assertThat(PlainPassword(CharBuffer.wrap(backingArray)))
        .prop(PlainPassword::asCharArray)
        .isSameInstanceAs(backingArray)
    }

    @Test
    fun asCharArrayReturnsNewlyInstantiatedArrayIfThePasswordIsNeitherEmptyNorHasOne() {
      val password = PlainPassword.newRandomWithNonDirectBuffer()
      assertThat(password)
        .prop(PlainPassword::asCharArray)
        .isNotSameInstanceAs(password.asCharArray())
    }
  }

  class ComparisonTests {
    @Test
    fun equalsOnlyComparesStructurally() {
      val originalPassword = PlainPassword.newRandomWithDirectBuffer()
      val clonedPassword = originalPassword.clone()
      assertThat(originalPassword).all {
        isEqualTo(clonedPassword)
        clonedPassword.discard()
        isNotEqualTo(clonedPassword)
      }
    }
  }

  class CodingTests {
    @Test
    fun codingIsSymmetric() {
      val decodedPassword = PlainPassword.newRandomWithDirectBuffer()
      val encodedPassword = decodedPassword.encode()
      assertThat(PlainPassword)
        .transform("decode(${encodedPassword.toList()})") {
          it.decode(encodedPassword)
        }
        .isEqualTo(decodedPassword)
    }
  }

  class CloningTests {
    @Test
    fun originalPasswordIsBackedByBufferIndependentFromThatOfClonedPassword() {
      val originalPassword = PlainPassword.newRandomWithDirectBuffer()
      val clonedPassword = originalPassword.clone()
      val clonedContents = clonedPassword.newCharArray()
      clonedPassword.discard()
      assertThat(originalPassword)
        .prop(PlainPassword::toList)
        .containsExactly(*clonedContents.toTypedArray())
    }

    @Test
    fun clonedPasswordIsBackedByBufferIndependentFromThatOfOriginalPassword() {
      val originalPassword = PlainPassword.newRandomWithDirectBuffer()
      val originalContents = originalPassword.newCharArray()
      val clonedPassword = originalPassword.clone()
      originalPassword.discard()
      assertThat(clonedPassword)
        .prop(PlainPassword::asCharArray)
        .containsExactly(*originalContents)
    }
  }

  class DiscardingTests {
    @Test
    fun discards() {
      val password = PlainPassword.newRandomWithDirectBuffer()
      password.discard()
      assertThat(password).isEmpty()
    }
  }

  @RunWith(JUnitParamsRunner::class)
  class GenerationTests {
    @JvmField @Rule val retryRule = RetryRule()

    @Parameters("-2", "0")
    @Test
    fun returnsEmptyStringIfGeneratingWithLengthZeroOrNegative(length: Int) {
      val generatedPassword =
        PlainPassword.generate(
          rng,
          PlainPassword.Letters.WITH_DIACRITICS,
          allowsDigits = true,
          allowsSymbols = true,
          length)
      assertThat(generatedPassword).isEmpty()
    }

    @Test
    fun returnsEmptyStringIfGeneratingWithoutCharacterSubset() {
      val generatedPassword =
        PlainPassword.generate(
          rng,
          PlainPassword.Letters.NONE,
          allowsDigits = false,
          allowsSymbols = false,
          length = 16)
      assertThat(generatedPassword).isEmpty()
    }

    @Parameters("2", "4", "16")
    @Test
    fun generates(length: Int) {
      val generatedPassword =
        PlainPassword.generate(
          rng,
          PlainPassword.Letters.WITH_DIACRITICS,
          allowsDigits = true,
          allowsSymbols = true,
          length)
      assertThat(generatedPassword).hasLength(length)
    }

    @Retry(times = 4)
    @Test
    fun generatesRandomly() {
      val letters = PlainPassword.Letters.WITH_DIACRITICS
      val allowsDigits = true
      val allowsSymbols = true
      val length = 16
      repeat(32) {
        assertThat(
            PlainPassword.generate(
              rng, letters, allowsDigits, allowsSymbols, length))
          .isNotEqualTo(
            PlainPassword.generate(
              rng, letters, allowsDigits, allowsSymbols, length))
      }
    }

    private companion object {
      @JvmStatic val rng: Random = ThreadLocalRandom.current()
    }
  }

  @RunWith(JUnitParamsRunner::class)
  class TOTPGenerationTests {
    @Test
    fun throwsIfKeyContainsLessThan128Bits() {
      val keySize = PlainPassword.TOTP_MIN_KEY_SIZE_IN_BYTES - 1
      assertFailure { PlainPassword.generateTOTP(newRandomKey(keySize)) }
        .isInstanceOf<PlainPassword.TOTPException.ShortKey>()
        .prop(PlainPassword.TOTPException.ShortKey::size)
        .isEqualTo(keySize)
    }

    @Test
    fun throwsIfStartTimeIsBeforeUnixEpoch() {
      val currentTime = (-2).seconds
      assertFailure { PlainPassword.generateTOTP(newRandomKey(), currentTime) }
        .isInstanceOf<PlainPassword.TOTPException.PreUnixEpochTime>()
        .prop(PlainPassword.TOTPException.PreUnixEpochTime::currentTime)
        .isEqualTo(currentTime)
    }

    @Test
    fun throwsIfLengthIsLesserThan6() =
      assertFailure { PlainPassword.generateTOTP(newRandomKey(), length = 5) }
        .isInstanceOf<PlainPassword.TOTPException.LowEntropy>()
        .prop(PlainPassword.TOTPException.LowEntropy::length)
        .isEqualTo(5)

    @Test
    fun throwsIfLengthIsGreaterThan8() =
      assertFailure { PlainPassword.generateTOTP(newRandomKey(), length = 9) }
        .isInstanceOf<PlainPassword.TOTPException.LowEntropy>()
        .prop(PlainPassword.TOTPException.LowEntropy::length)
        .isEqualTo(9)

    @Test
    fun generates6DigitLongTOTPByDefault() =
      assertThat(PlainPassword.generateTOTP(newRandomKey())).hasLength(6)

    @Test
    fun generatesEqualTOTPsIfTheirKeyAndCurrentTimeAreEqual() {
      val key = newRandomKey()
      val currentTime = 64.seconds
      assertThat(PlainPassword.generateTOTP(key, currentTime))
        .isEqualTo(PlainPassword.generateTOTP(key, currentTime))
    }

    @Parameters("SHA1", "SHA256", "SHA512")
    @Test
    fun generatesUsingHashFunction(
      hashFunction: PlainPassword.TOTPHashFunction
    ) =
      assertThat(
          PlainPassword.generateTOTP(
            newRandomKey(), hashFunction = hashFunction))
        .hasLength(6)

    @Parameters("6", "7", "8")
    @Test
    fun generatesWithLength(length: Int) =
      assertThat(PlainPassword.generateTOTP(newRandomKey(), length = length))
        .hasLength(length)

    private companion object {
      @JvmStatic
      fun newRandomKey(
        size: Int = PlainPassword.TOTP_MIN_KEY_SIZE_IN_BYTES
      ): ByteArray {
        val key = ByteArray(size)
        ThreadLocalRandom.current().nextBytes(key)
        return key
      }
    }
  }
}
