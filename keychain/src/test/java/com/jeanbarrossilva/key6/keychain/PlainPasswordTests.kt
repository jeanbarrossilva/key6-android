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
import assertk.assertThat
import assertk.assertions.containsExactly
import assertk.assertions.hasLength
import assertk.assertions.isEmpty
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEqualTo
import assertk.assertions.prop
import com.jeanbarrossilva.key6.keychain.test.newSample
import com.jeanbarrossilva.key6.keychain.test.newSampleBackingBuffer
import com.kevinmost.junit_retry_rule.Retry
import com.kevinmost.junit_retry_rule.RetryRule
import java.util.concurrent.ThreadLocalRandom
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Suite

@RunWith(Suite::class)
@Suite.SuiteClasses(
  PlainPasswordTests.CloningTests::class,
  PlainPasswordTests.CodingTests::class,
  PlainPasswordTests.ComparisonTests::class,
  PlainPasswordTests.DiscardingTests::class,
  PlainPasswordTests.GenerationTests::class)
internal class PlainPasswordTests {
  class ComparisonTests {
    @Test
    fun equalsOnlyComparesStructurally() {
      val onePassword = PlainPassword.newSample()
      assertThat(onePassword).all {
        val anotherPassword = PlainPassword.newSample()
        isEqualTo(anotherPassword)
        anotherPassword.discard()
        isNotEqualTo(anotherPassword)
      }
    }
  }

  class CodingTests {
    @Test
    fun codingIsSymmetric() {
      val decodedPassword = PlainPassword.newSample()
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
      val originalPassword = PlainPassword.newSample()
      val clonedPassword = originalPassword.clone()
      clonedPassword.discard()
      assertThat(originalPassword)
        .prop(PlainPassword::toList)
        .containsExactly(
          *PlainPassword.newSampleBackingBuffer().toList().toTypedArray())
    }

    @Test
    fun clonedPasswordIsBackedByBufferIndependentFromThatOfOriginalPassword() {
      val originalPassword = PlainPassword.newSample()
      val clonedPassword = originalPassword.clone()
      originalPassword.discard()
      assertThat(clonedPassword)
        .prop(PlainPassword::toList)
        .containsExactly(
          *PlainPassword.newSampleBackingBuffer().toList().toTypedArray())
    }
  }

  class DiscardingTests {
    @Test
    fun discards() {
      val password = PlainPassword.newSample()
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
      repeat(32) {
        assertThat(
            PlainPassword.generate(
              rng,
              PlainPassword.Letters.WITH_DIACRITICS,
              allowsDigits = true,
              allowsSymbols = true,
              length = 16))
          .isNotEqualTo(
            PlainPassword.generate(
              rng,
              PlainPassword.Letters.WITH_DIACRITICS,
              allowsDigits = true,
              allowsSymbols = true,
              length = 16))
      }
    }
  }

  private companion object {
    @JvmStatic val rng: ThreadLocalRandom = ThreadLocalRandom.current()
  }
}
