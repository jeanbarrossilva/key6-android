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
import assertk.assertions.containsExactly
import assertk.assertions.isEmpty
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import assertk.assertions.isNotEqualTo
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Suite

@RunWith(Suite::class)
@Suite.SuiteClasses(ConsecutionTests::class)
class CharSequenceCountTests

@RunWith(JUnitParamsRunner::class)
class ConsecutionTests {
  @Parameters("-1", "0", "1")
  @Test
  fun assertionFailsIfCountIsLessThan2(count: Int) {
    assertFailure { Consecution(index = 0, ' ', count) }
      .isInstanceOf<AssertionError>()
  }

  @Test
  fun comparesConsecutions() {
    assertThat(Consecution(index = 0, ' ', count = 2)).all {
      isEqualTo(Consecution(index = 0, ' ', count = 2))
      isNotEqualTo(Consecution(index = 2, ' ', count = 2))
      isNotEqualTo(Consecution(index = 0, '…', count = 2))
      isNotEqualTo(Consecution(index = 0, ' ', count = 4))
    }
  }

  @Parameters("", " ", "John")
  @Test
  fun returnsEmptyListWhenTryingToFindConsecutionsOfSequenceWithoutConsecutions(
    characters: String
  ) {
    assertThat(characters.toCharArray())
      .transform("findConsecutions(Char::isWhitespace)") {
        it.findConsecutions(Char::isWhitespace)
      }
      .isEmpty()
  }

  @Test
  fun findsConsecutions() {
    assertThat(
        charArrayOf(
          '1', ' ', '2', ' ', ' ', '3', ' ', ' ', ' ', '4', ' ', ' ', ' ', ' '))
      .transform("findConsecutions(Char::isWhitespace)") {
        it.findConsecutions(Char::isWhitespace)
      }
      .containsExactly(
        Consecution(index = 3, character = ' ', count = 2),
        Consecution(index = 6, character = ' ', count = 3),
        Consecution(index = 10, character = ' ', count = 4))
  }
}
