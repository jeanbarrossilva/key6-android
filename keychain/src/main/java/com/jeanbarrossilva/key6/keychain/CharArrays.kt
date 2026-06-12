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

import java.util.Objects

/**
 * Description of consecutive occurrences of a character in a sequence.
 *
 * @see CharArray.findConsecutions
 */
class Consecution {
  /**
   * Index at which the last character of this consecution is.
   *
   * @see startIndex
   */
  val endIndex: Int
    get() = startIndex + count - 1

  /**
   * Index at which the first character of this consecution is.
   *
   * @see endIndex
   */
  val startIndex: Int

  /** The character repeated consecutively. */
  val character: Char

  /** Amount of times the character is repeated consecutively. */
  var count: Int
    internal set

  @Throws(AssertionError::class)
  internal constructor(index: Int, character: Char, count: Int) {
    assert(count >= 2) { "Amount of consecutive characters should be ≥ 2." }
    this.startIndex = index
    this.character = character
    this.count = count
  }

  override fun equals(other: Any?) =
    other is Consecution &&
      startIndex == other.startIndex &&
      character == other.character &&
      count == other.count

  override fun hashCode() = Objects.hash(startIndex, character, count)

  override fun toString() =
    "Consecution(startIndex=$startIndex, character=$character, count=$count)"
}

/**
 * Searches for the amount of consecutive occurrences of characters in this
 * array, alongside with their indices.
 *
 * @param predicate Determines whether the given character should be considered
 *   as part of a consecution in case others matching this predicate are
 *   adjacent to this character.
 * @return The amount of times certain characters were repeated consecutively,
 *   and the indices at which these repetitions started in this array.
 */
internal fun CharArray.findConsecutions(
  predicate: (Char) -> Boolean
): List<Consecution> {
  if (size < 2) return emptyList()
  var consecutions: ArrayList<Consecution>? = null
  var wasInConsecution = false
  for ((characterIndex, character) in withIndex()) if (predicate(character))
    if (!wasInConsecution) wasInConsecution = true
    else {
      val consecutionIndex = characterIndex - 1
      val consecutionCount = 2
      if (consecutions == null) {
        consecutions = ArrayList()
        consecutions.add(
          Consecution(consecutionIndex, character, consecutionCount))
        wasInConsecution = true
      } else {
        val lastConsecution = consecutions.last()
        if (lastConsecution.endIndex + 1 == characterIndex &&
          lastConsecution.character == character)
          lastConsecution.count++
        else
          consecutions.add(Consecution(consecutionIndex, character, count = 2))
      }
    }
  else wasInConsecution = false
  return consecutions ?: emptyList()
}
