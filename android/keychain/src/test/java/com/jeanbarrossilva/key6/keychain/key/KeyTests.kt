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
import assertk.assertions.containsOnly
import assertk.assertions.hasSize
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import assertk.assertions.prop
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import org.junit.Test
import org.junit.runner.RunWith

@OptIn(ExperimentalUuidApi::class)
@RunWith(JUnitParamsRunner::class)
internal class KeyTests {
  @Test
  fun instantiatesZeroed16ByteSalt() {
    val salt = Key.newZeroedSalt()
    assertThat(salt).all {
      hasSize(16)
      containsOnly(0)
    }
  }

  @Test
  fun instantiatesZeroed12ByteIV() {
    val iv = Key.newZeroedIV()
    assertThat(iv).all {
      hasSize(12)
      containsOnly(0)
    }
  }

  @Parameters(
    ", -1",
    " , -1",
    "6fa459ea-ee8a-11e0-9000-0800200c9a66, 1",
    "9073926b-929f-31c2-abc9-fad77ae3e8eb, 3",
    "550e8400-e29b-41d4-a716-446655440000, 4",
    "cfbff0d1-9375-5685-968c-48ce8b15ae17, 5"
  )
  @Suppress("SpellCheckingInspection")
  @Test
  fun throwsIfInstantiatingKeyWithNonV7Uuid(
    id: String,
    version: Int
  ) {
    assertFailure {
      Key.new(
        id,
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        salt = ByteArray(size = 16),
        iv = ByteArray(size = 12),
        encryptedPassword = ByteArray(size = 8),
        path = null
      )
    }.isInstanceOf<KeyException.NonUuidV7ID>()
      .prop(KeyException.NonUuidV7ID::version)
      .isEqualTo(version.takeIf { it >= 0 })
  }

  @Parameters("8", "12")
  @Test
  fun throwsIfInstantiatingKeyWithNon16ByteSalt(size: Int) {
    assertFailure {
      Key.new(
        Uuid.generateV7().toString(),
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        salt = ByteArray(size),
        iv = ByteArray(size = 12),
        encryptedPassword = ByteArray(size = 8),
        path = null
      )
    }.isInstanceOf<KeyException.Non16ByteSalt>()
      .prop(KeyException.Non16ByteSalt::size)
      .isEqualTo(size)
  }

  @Parameters("8", "16")
  @Test
  fun throwsIfInstantiatingKeyWithNon12ByteIV(size: Int) {
    assertFailure {
      Key.new(
        Uuid.generateV7().toString(),
        title = "Lorem ipsum",
        login = "john@appleseed.com",
        salt = ByteArray(size = 16),
        iv = ByteArray(size),
        encryptedPassword = ByteArray(size = 8),
        path = null
      )
    }.isInstanceOf<KeyException.Non12ByteIV>()
      .prop(KeyException.Non12ByteIV::size)
      .isEqualTo(size)
  }
}
