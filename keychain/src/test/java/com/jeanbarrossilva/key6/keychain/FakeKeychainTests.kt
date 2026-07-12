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
import assertk.assertions.isNotIn
import assertk.assertions.prop
import com.kevinmost.junit_retry_rule.Retry
import com.kevinmost.junit_retry_rule.RetryRule
import org.junit.Rule
import org.junit.Test

internal class FakeKeychainTests {
  @JvmField @Rule val retryRule = RetryRule()

  @Retry(times = 4)
  @Test
  fun isInstantiatedWithRandomMainPassword() {
    repeat(32) {
      val firstKeychain = FakeKeychain.withRandomMainPassword()
      val secondKeychain = FakeKeychain.withRandomMainPassword()
      assertThat(secondKeychain)
        .prop(FakeKeychain::mainPassword)
        .isNotIn(firstKeychain.mainPassword)
    }
  }
}
