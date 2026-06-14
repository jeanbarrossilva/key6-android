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
import java.nio.CharBuffer

/**
 * Instantiates a sample password for testing, whose buffer is one returned by
 * [newSampleBackingBuffer].
 */
internal fun PlainPassword.Companion.newSample() =
  PlainPassword(newSampleBackingBuffer())

/**
 * Produces a populated backing buffer of a plain password for testing. Despite
 * being distinct instances, the contents of unmodified buffers returned by two
 * calls to this method will be equal, such that
 *
 * - `newBackingBuffer() !== newBackingBuffer()`; and
 * - `newBackingBuffer().contentEquals(newBackingBuffer())`.
 */
internal fun PlainPassword.Companion.newSampleBackingBuffer(): CharBuffer {
  val backingBuffer = CharBuffer.allocate(9)
  backingBuffer.put('a')
  backingBuffer.put('p')
  backingBuffer.put('p')
  backingBuffer.put('l')
  backingBuffer.put('e')
  backingBuffer.put('s')
  backingBuffer.put('e')
  backingBuffer.put('e')
  backingBuffer.put('d')
  backingBuffer.rewind()
  return backingBuffer
}
