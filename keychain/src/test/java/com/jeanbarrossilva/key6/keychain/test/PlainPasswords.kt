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

@file:JvmName("PlainPasswords")

package com.jeanbarrossilva.key6.keychain.test

import com.jeanbarrossilva.key6.keychain.PlainPassword
import com.jeanbarrossilva.key6.keychain.discard
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.Random
import java.util.concurrent.ThreadLocalRandom

/** Amount of characters in a password generated for testing purposes. */
private const val LENGTH = 128

/** Alphabet indexed by the [rng] for generating random passwords in tests. */
private val generationAlphabet =
  PlainPassword.newGenerationAlphabet(
    PlainPassword.Letters.WITHOUT_DIACRITICS,
    allowsDigits = true,
    allowsSymbols = true)

/** Instantiates a random password backed by a direct buffer. */
internal fun PlainPassword.Companion.newRandomWithDirectBuffer() =
  PlainPassword(newDirectRandomBackingBuffer())

/** Instantiates a random password backed by a non-direct buffer. */
internal fun PlainPassword.Companion.newRandomWithNonDirectBuffer() =
  PlainPassword(newNonDirectRandomBackingBuffer())

/** Instantiates a randomly-populated, non-direct buffer of a plain password. */
internal fun PlainPassword.Companion.newNonDirectRandomBackingBuffer():
  CharBuffer {
  val encodedPasswordBuffer = charset.encode(newDirectRandomBackingBuffer())
  val backingBuffer: ByteBuffer =
    ByteBuffer.allocateDirect(encodedPasswordBuffer.limit())
  while (encodedPasswordBuffer.hasRemaining()) {
    val index = encodedPasswordBuffer.position()
    backingBuffer.put(encodedPasswordBuffer[index])
    encodedPasswordBuffer.put(index, 0)
    encodedPasswordBuffer.position(index + 1)
  }
  encodedPasswordBuffer.discard {}
  return backingBuffer.rewind().asCharBuffer()
}

/** Instantiates a randomly-populated, direct buffer of a plain password. */
internal fun PlainPassword.Companion.newDirectRandomBackingBuffer() =
  newPopulatedGenerationBackingBuffer(rng(), generationAlphabet, LENGTH)

/** Instantiates a randomly-populated backing array of a plain password. */
internal fun PlainPassword.Companion.newRandomBackingArray(): CharArray {
  val rng = rng()
  val backingArray = CharArray(LENGTH)
  for (index in 0..<backingArray.size) backingArray[index] =
    generationAlphabet[rng.nextInt(generationAlphabet.size)]
  return backingArray
}

/** Obtains the RNG responsible for generating random passwords in tests. */
private fun rng(): Random = ThreadLocalRandom.current()
