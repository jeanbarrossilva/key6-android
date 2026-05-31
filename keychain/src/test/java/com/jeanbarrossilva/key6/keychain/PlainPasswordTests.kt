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
import assertk.assertions.hasSize
import assertk.assertions.isEmpty
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotEqualTo
import com.kevinmost.junit_retry_rule.Retry
import com.kevinmost.junit_retry_rule.RetryRule
import java.util.concurrent.ThreadLocalRandom
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(JUnitParamsRunner::class)
internal class PlainPasswordTests {
  @JvmField @Rule val retryRule = RetryRule()

  @Test
  fun throwsIfRngIsNull() {
    assertFailure {
        PlainPassword.generate(
          /* rng = */ null,
          PlainPassword.Letters.NONE,
          /* allowsDigits = */ false,
          /* allowsSymbols = */ false,
          /* length = */ 8)
      }
      .isInstanceOf<NullPointerException>()
  }

  @Parameters("-2", "0")
  @Test
  fun returnsEmptyStringIfGeneratingWithLengthZeroOrNegative(length: Int) {
    val generatedPlainPassword =
      PlainPassword.generate(
        rng,
        PlainPassword.Letters.WITH_DIACRITICS,
        /* allowsDigits = */ true,
        /* allowsSymbols = */ true,
        length)
    assertThat(generatedPlainPassword).isEmpty()
  }

  @Test
  fun returnsEmptyStringIfGeneratingWithoutCharacterSubset() {
    val generatedPlainPassword =
      PlainPassword.generate(
        rng,
        PlainPassword.Letters.NONE,
        /* allowsDigits = */ false,
        /* allowsSymbols = */ false,
        /* length = */ 16)
    assertThat(generatedPlainPassword).isEmpty()
  }

  @Parameters("2", "4", "16")
  @Test
  fun generates(length: Int) {
    val generatedPlainPassword =
      PlainPassword.generate(
        rng,
        PlainPassword.Letters.WITH_DIACRITICS,
        /* allowsDigits = */ true,
        /* allowsSymbols = */ true,
        length)
    assertThat(generatedPlainPassword).hasSize(length)
  }

  @Retry(times = 4)
  @Test
  fun generatesRandomly() {
    repeat(32) {
      assertThat(
          PlainPassword.generate(
            rng,
            PlainPassword.Letters.WITH_DIACRITICS,
            /* allowsDigits = */ true,
            /* allowsSymbols = */ true,
            /* length = */ 16))
        .isNotEqualTo(
          PlainPassword.generate(
            rng,
            PlainPassword.Letters.WITH_DIACRITICS,
            /* allowsDigits = */ true,
            /* allowsSymbols = */ true,
            /* length = */ 16))
    }
  }

  private companion object {
    @JvmStatic val rng: ThreadLocalRandom = ThreadLocalRandom.current()
  }
}
