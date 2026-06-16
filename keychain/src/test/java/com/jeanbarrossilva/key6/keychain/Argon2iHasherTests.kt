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

import assertk.assertThat
import assertk.assertions.isFalse
import assertk.assertions.isTrue
import com.jeanbarrossilva.key6.keychain.test.newRandomWithDirectBuffer
import io.mockk.clearMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.security.SecureRandom
import org.junit.Test

internal class Argon2iHasherTests {
  @Test
  fun returnsFalseUponMatchAgainstUnhashedPassword() {
    val hasher = newHasher()
    val password = PlainPassword.newRandomWithDirectBuffer()
    assertThat(hasher)
      .transform("matches(${password.toList()})") { it.isMatch(password) }
      .isFalse()
  }

  @Test
  fun saltIsGeneratedByGivenCsprng() {
    val hasherCsprng = mockk<SecureRandom>()
    val ourCsprng = SecureRandom()
    every { hasherCsprng.nextBytes(Argon2iHasher.newZeroedSalt()) } answers
      {
        ourCsprng.nextBytes(firstArg())
      }
    val hasher = newHasher(hasherCsprng)
    val password = PlainPassword.newRandomWithDirectBuffer()
    hasher.hash(password)
    verify { hasherCsprng.nextBytes(any()) }
    clearMocks(hasherCsprng)
  }

  @Test
  fun returnsTrueIfPasswordIsMatchedAgainstHashedEqualOne() {
    val hasher = newHasher()
    val password = PlainPassword.newRandomWithDirectBuffer()
    hasher.hash(password)
    assertThat(hasher)
      .transform("matches(${password.toList()})") { it.isMatch(password) }
      .isTrue()
  }
}

private fun newHasher(csprng: SecureRandom = SecureRandom()) =
  Argon2iHasher(csprng)
