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
import assertk.assertions.hasToString
import assertk.assertions.isEmpty
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotEqualTo
import assertk.assertions.isNotSameInstanceAs
import assertk.assertions.isSameInstanceAs
import assertk.assertions.prop
import com.jeanbarrossilva.key6.keychain.key.PlainPassword.Companion.TOTP_MIN_KEY_SIZE_IN_BYTES
import com.jeanbarrossilva.key6.keychain.key.PlainPassword.Companion.generateTOTP
import com.jeanbarrossilva.key6.keychain.key.PlainPassword.TOTPException
import com.jeanbarrossilva.key6.keychain.key.PlainPassword.TOTPHashFunction
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
  PlainPasswordTests.TOTPTests::class)
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
          RNG,
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
          RNG,
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
          RNG,
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
              RNG, letters, allowsDigits, allowsSymbols, length))
          .isNotEqualTo(
            PlainPassword.generate(
              RNG, letters, allowsDigits, allowsSymbols, length))
      }
    }

    private companion object {
      @JvmStatic val RNG: Random = ThreadLocalRandom.current()
    }
  }

  @RunWith(Suite::class)
  @Suite.SuiteClasses(
    TOTPTests.GenerationTests::class, TOTPTests.RFCTests::class)
  class TOTPTests {
    @RunWith(JUnitParamsRunner::class)
    class GenerationTests {
      @Test
      fun throwsIfKeyContainsLessThan128Bits() {
        val keySize = TOTP_MIN_KEY_SIZE_IN_BYTES - 1
        assertFailure { generateTOTP(newRandomKey(keySize)) }
          .isInstanceOf<TOTPException.ShortSeed>()
          .prop(TOTPException.ShortSeed::size)
          .isEqualTo(keySize)
      }

      @Test
      fun throwsIfCurrentTimeIsBeforeUnixEpoch() {
        val currentTime = (-2).seconds
        assertFailure { generateTOTP(newRandomKey(), currentTime) }
          .isInstanceOf<TOTPException.PreUnixEpochTime>()
          .prop(TOTPException.PreUnixEpochTime::currentTime)
          .isEqualTo(currentTime)
      }

      @Test
      fun throwsIfLengthIsLesserThan6() {
        val length = 5
        assertFailure { generateTOTP(newRandomKey(), length = length) }
          .isInstanceOf<TOTPException.LowEntropy>()
          .prop(TOTPException.LowEntropy::length)
          .isEqualTo(length)
      }

      @Test
      fun throwsIfLengthIsGreaterThan8() {
        val length = 9
        assertFailure { generateTOTP(newRandomKey(), length = length) }
          .isInstanceOf<TOTPException.LowEntropy>()
          .prop(TOTPException.LowEntropy::length)
          .isEqualTo(length)
      }

      @Test
      fun generates6DigitLongTOTPByDefault() =
        assertThat(generateTOTP(newRandomKey())).hasLength(6)

      @Test
      fun generatesEqualTOTPsIfTheirKeyAndCurrentTimeAreEqual() {
        val key = newRandomKey()
        val currentTime = 64.seconds
        assertThat(generateTOTP(key, currentTime))
          .isEqualTo(generateTOTP(key, currentTime))
      }

      @Parameters("SHA1", "SHA256", "SHA512")
      @Test
      fun generatesUsingHashFunction(hashFunction: TOTPHashFunction) =
        assertThat(generateTOTP(newRandomKey(), hashFunction = hashFunction))
          .hasLength(6)

      @Parameters("6", "7", "8")
      @Test
      fun generatesWithLength(length: Int) =
        assertThat(generateTOTP(newRandomKey(), length = length))
          .hasLength(length)

      private companion object {
        @JvmStatic
        fun newRandomKey(size: Int = TOTP_MIN_KEY_SIZE_IN_BYTES): ByteArray {
          val key = ByteArray(size)
          ThreadLocalRandom.current().nextBytes(key)
          return key
        }
      }
    }

    class RFCTests {
      // These cases are based on the Appendix B table of the TOTP RFC.
      // https://www.rfc-editor.org/info/rfc6238/#appendix-B

      @Test
      fun case1() =
        assertThat(
            generateTOTP(SHA1_SEED, currentTime = 59.seconds, length = LENGTH))
          .hasToString("94287082")

      @Test
      fun case2() =
        assertThat(
            generateTOTP(
              SHA256_SEED,
              currentTime = 59.seconds,
              hashFunction = TOTPHashFunction.SHA256,
              length = LENGTH))
          .hasToString("46119246")

      @Test
      fun case3() =
        assertThat(
            generateTOTP(
              SHA512_SEED,
              currentTime = 59.seconds,
              hashFunction = TOTPHashFunction.SHA512,
              length = LENGTH))
          .hasToString("90693936")

      @Test
      fun case4() =
        assertThat(
            generateTOTP(
              SHA1_SEED, currentTime = 1111111109.seconds, length = LENGTH))
          .hasToString("07081804")

      @Test
      fun case5() =
        assertThat(
            generateTOTP(
              SHA256_SEED,
              currentTime = 1111111109.seconds,
              hashFunction = TOTPHashFunction.SHA256,
              length = LENGTH))
          .hasToString("68084774")

      @Test
      fun case6() =
        assertThat(
            generateTOTP(
              SHA512_SEED,
              currentTime = 1111111109.seconds,
              hashFunction = TOTPHashFunction.SHA512,
              length = LENGTH))
          .hasToString("25091201")

      @Test
      fun case7() =
        assertThat(
            generateTOTP(
              SHA1_SEED, currentTime = 1111111111.seconds, length = LENGTH))
          .hasToString("14050471")

      @Test
      fun case8() =
        assertThat(
            generateTOTP(
              SHA256_SEED,
              currentTime = 1111111111.seconds,
              hashFunction = TOTPHashFunction.SHA256,
              length = LENGTH))
          .hasToString("67062674")

      @Test
      fun case9() =
        assertThat(
            generateTOTP(
              SHA512_SEED,
              currentTime = 1111111111.seconds,
              hashFunction = TOTPHashFunction.SHA512,
              length = LENGTH))
          .hasToString("99943326")

      @Test
      fun case10() =
        assertThat(
            generateTOTP(
              SHA1_SEED, currentTime = 1234567890.seconds, length = LENGTH))
          .hasToString("89005924")

      @Test
      fun case11() =
        assertThat(
            generateTOTP(
              SHA256_SEED,
              currentTime = 1234567890.seconds,
              hashFunction = TOTPHashFunction.SHA256,
              length = LENGTH))
          .hasToString("91819424")

      @Test
      fun case12() =
        assertThat(
            generateTOTP(
              SHA512_SEED,
              currentTime = 1234567890.seconds,
              hashFunction = TOTPHashFunction.SHA512,
              length = LENGTH))
          .hasToString("93441116")

      @Test
      fun case13() =
        assertThat(
            generateTOTP(
              SHA1_SEED, currentTime = 2000000000.seconds, length = LENGTH))
          .hasToString("69279037")

      @Test
      fun case14() =
        assertThat(
            generateTOTP(
              SHA256_SEED,
              currentTime = 2000000000.seconds,
              hashFunction = TOTPHashFunction.SHA256,
              length = LENGTH))
          .hasToString("90698825")

      @Test
      fun case15() =
        assertThat(
            generateTOTP(
              SHA512_SEED,
              currentTime = 2000000000.seconds,
              hashFunction = TOTPHashFunction.SHA512,
              length = LENGTH))
          .hasToString("38618901")

      @Test
      fun case16() =
        assertThat(
            generateTOTP(
              SHA1_SEED, currentTime = 20000000000.seconds, length = LENGTH))
          .hasToString("65353130")

      @Test
      fun case17() =
        assertThat(
            generateTOTP(
              SHA256_SEED,
              currentTime = 20000000000.seconds,
              hashFunction = TOTPHashFunction.SHA256,
              length = LENGTH))
          .hasToString("77737706")

      @Test
      fun case18() =
        assertThat(
            generateTOTP(
              SHA512_SEED,
              currentTime = 20000000000.seconds,
              hashFunction = TOTPHashFunction.SHA512,
              length = LENGTH))
          .hasToString("47863826")

      private companion object {
        const val LENGTH = 8

        val SHA1_SEED = "12345678901234567890".toByteArray()
        val SHA256_SEED = "12345678901234567890123456789012".toByteArray()
        val SHA512_SEED =
          "1234567890123456789012345678901234567890123456789012345678901234"
            .toByteArray()
      }
    }
  }
}
