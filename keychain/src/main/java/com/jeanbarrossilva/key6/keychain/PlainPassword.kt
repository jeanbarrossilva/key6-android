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

package com.jeanbarrossilva.key6.keychain

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.Random

/**
 * Secret for authenticating at a site, in plaintext (i.e., non-encrypted and/or
 * non-hashed).
 *
 * @property backingBuffer Buffer of characters which compose this plain
 *   password. Changes to it affect the contents of the password.
 */
@JvmInline
value class PlainPassword(private val backingBuffer: CharBuffer) :
  CharSequence {
  override val length: Int
    get() = backingBuffer.length

  /**
   * Whether this password is backed by a buffer which is backed by an array.
   */
  private val hasArray
    get() = backingBuffer.hasArray()

  /**
   * Selector of letters (including none) that a plain, generated password can
   * include.
   */
  enum class Letters {
    /** No letters will be included. */
    NONE {
      override val subset: CharArray = empty.backingBuffer.array()
    },

    /** Only letters without combining diacritics may be included. */
    WITHOUT_DIACRITICS {
      override val subset =
        charArrayOf(
          'A',
          'a',
          'B',
          'b',
          'C',
          'c',
          'D',
          'd',
          'E',
          'e',
          'F',
          'f',
          'G',
          'g',
          'H',
          'h',
          'I',
          'i',
          'J',
          'j',
          'K',
          'k',
          'L',
          'l',
          'M',
          'm',
          'N',
          'n',
          'O',
          'o',
          'P',
          'p',
          'Q',
          'q',
          'R',
          'r',
          'S',
          's',
          'T',
          't',
          'U',
          'u',
          'V',
          'v',
          'W',
          'w',
          'X',
          'x',
          'Y',
          'y',
          'Z',
          'z')
    },

    /** Letters both with and without combining diacritics may be included. */
    WITH_DIACRITICS {
      override val subset =
        charArrayOf(
          'A',
          'À',
          'Á',
          'Â',
          'Ã',
          'Ä',
          'Å',
          'Æ',
          'a',
          'à',
          'á',
          'â',
          'ã',
          'ä',
          'å',
          'æ',
          'B',
          'b',
          'C',
          'Ç',
          'c',
          'ç',
          'D',
          'Ð',
          'd',
          'ð',
          'E',
          'È',
          'É',
          'Ê',
          'Ë',
          'e',
          'è',
          'é',
          'ê',
          'ë',
          'F',
          'f',
          'G',
          'g',
          'H',
          'h',
          'I',
          'Ì',
          'Í',
          'Î',
          'Ï',
          'i',
          'ì',
          'í',
          'î',
          'ï',
          'J',
          'j',
          'K',
          'k',
          'L',
          'l',
          'M',
          'm',
          'N',
          'Ñ',
          'n',
          'ñ',
          'O',
          'Ò',
          'Ó',
          'Ô',
          'Õ',
          'Ö',
          'Ø',
          'o',
          'ò',
          'ó',
          'ô',
          'õ',
          'ö',
          'ø',
          'P',
          'p',
          'Q',
          'q',
          'R',
          'r',
          'S',
          's',
          'T',
          't',
          'U',
          'Ù',
          'Ú',
          'Û',
          'Ü',
          'u',
          'ù',
          'ú',
          'û',
          'ü',
          'V',
          'v',
          'W',
          'w',
          'X',
          'x',
          'Y',
          'Ý',
          'y',
          'ý',
          'ÿ',
          'Z',
          'z',
          'Þ',
          'þ')
    };

    /** Characters encompassed by this selector. */
    abstract val subset: CharArray
  }

  override fun get(index: Int) = backingBuffer[index]

  override fun subSequence(startIndex: Int, endIndex: Int) =
    backingBuffer.subSequence(startIndex, endIndex)

  override fun toString() = backingBuffer.toString()

  /**
   * Returns a password whose contents equal those of this one, backed by an
   * independent buffer: changes to the contents of this password **will not**
   * affect those of the returned clone, and vice versa.
   */
  fun clone(): PlainPassword {
    if (isEmpty()) return empty
    val clonedBackingBuffer = backingBuffer.clone()
    return PlainPassword(clonedBackingBuffer)
  }

  /**
   * Discards the contents of this password, preventing it from being read by
   * other processes. This method **must** be called as soon as this password
   * has been used and will not be referenced by Key6 anymore.
   */
  fun discard() {
    if (isEmpty()) return
    if (hasArray) backingBuffer.array().discard()
    backingBuffer.rewind().limit(0)
  }

  /**
   * Returns an array containing the bytes of the UTF-16-encoded contents of
   * this password.
   *
   * This method is the opposite of [decode], which takes in bytes of some
   * UTF-16-encoded password; such symmetry denotes that
   * `Companion.decode(encode()) == this`.
   */
  internal fun encode() =
    // 'Charset.encode(CharBuffer)' may search for the UTF-16 encoder, but there
    // will be no character to encode in case this password is empty. We avoid
    // that unnecessary work here.
    if (isEmpty()) byteArrayOf()
    else {
      val encodedPasswordBuffer = charset.encode(backingBuffer)
      backingBuffer.rewind()
      encodedPasswordBuffer
        // This array, by itself, is padded by 16 bytes; this implies
        // in its size being greater than the actual amount of UTF-16-encoded
        // characters in it. We trim that padding by returning a slice ranging
        // from the start of the array to the limit of the buffer—which is the
        // size of the array without the trailing padding.
        .array()
        .sliceArray(0..<encodedPasswordBuffer.limit())
    }

  /**
   * Returns an array containing the characters of this password.
   *
   * @return If:
   * - this password is empty, the same empty array;
   * - else, if this password has an array, that backing array;
   * - else, a newly-instantiated array, filled with the contents of this
   *   password.
   *
   * In the latter case, `discard(CharArray)`—rather than `discard()`—**must**
   * be called afterward: because the array was instantiated by this method and,
   * thus, **does not** back this password, discarding without passing the array
   * in will result in the password still being in the array.
   */
  internal fun asCharArray(): CharArray {
    if (isEmpty()) return empty.backingBuffer.array()
    if (hasArray) return backingBuffer.array()
    val charArray = CharArray(length)
    for (index in 0..<charArray.size) charArray[index] = this[index]
    return charArray
  }

  /**
   * Discards the contents **only** of the given array, and **only** in case
   * this password does not have an array: not having one would mean that
   * [asCharArray] returns an independent array, that would not be discarded
   * upon this password being discarded.
   *
   * @param charArray This password as an array of characters. Implied to have
   *   resulted from calling [asCharArray] on this password.
   */
  internal fun discard(charArray: CharArray) {
    // There being an array denotes that the return of the password–array
    // conversion *is* the backing array of this password's buffer (assuming
    // that given array has been returned by 'asCharArray()', 'characters' ===
    // 'toCharArray()' === 'backingBuffer.array()'); no need to proceed with the
    // O(n) array-discarding.
    if (hasArray) return

    charArray.discard()
  }

  companion object {
    /** Plain password without contents. */
    @JvmStatic private val empty = PlainPassword(CharBuffer.allocate(0))

    /** Charset in which plain passwords are coded: UTF-16. */
    private val charset = Charsets.UTF_16

    /** Numbers 0–9 as characters. */
    @JvmStatic
    private val digitSubset =
      charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')

    /**
     * Punctuation and other characters deemed special and printable in ASCII.
     */
    @JvmStatic
    private val symbolSubset =
      charArrayOf(
        '!',
        '"',
        '#',
        '$',
        '%',
        '&',
        '\'',
        '(',
        ')',
        '*',
        '+',
        ',',
        '-',
        '.',
        '/',
        ':',
        ';',
        '<',
        '=',
        '>',
        '?',
        '@',
        '[',
        '\\',
        ']',
        '^',
        '_',
        '`',
        '{',
        '|',
        '}',
        '~')

    /**
     * Instantiates a password from a [ByteArray], containing the bytes resulted
     * from encoding the characters of the original password.
     *
     * @param encodedPassword The UTF-16-encoded password to decode.
     * @see encode
     */
    @JvmStatic
    internal fun decode(encodedPassword: ByteArray) =
      if (encodedPassword.isEmpty()) empty
      else PlainPassword(charset.decode(ByteBuffer.wrap(encodedPassword)))

    /**
     * Generates a password in plaintext for some keychain.
     *
     * **NOTE**: To ensure that other processes cannot read the generated
     * password, discard it immediately after it has been used.
     *
     * @param rng Random number generator (RNG) for indexing the password's
     *   characters.
     * @param allowsDigits Whether the password may contain numbers.
     * @param allowsSymbols Whether the password may contain non-alphanumeric
     *   characters.
     * @param length Length of the password.
     * @return The generated plain password, empty in case [length] ≤ 0.
     * @see discard
     */
    @JvmStatic
    internal fun generate(
      rng: Random,
      letters: Letters,
      allowsDigits: Boolean,
      allowsSymbols: Boolean,
      length: Int
    ): PlainPassword {
      if (length <= 0) return empty
      val alphabet =
        letters.subset +
          (if (allowsDigits) digitSubset else charArrayOf()) +
          (if (allowsSymbols) symbolSubset else charArrayOf())
      if (alphabet.isEmpty()) return empty
      val backingBuffer = CharBuffer.allocate(length)
      for (index in 0..<length) backingBuffer.put(
        index, alphabet[rng.nextInt(alphabet.size)])
      backingBuffer.rewind()
      return PlainPassword(backingBuffer)
    }
  }
}

// Yes, there are the '*Array.fill(Char)' functions. However, one of my defects
// is that I *love* micro-optimizing, and they may perform a range check first;
// our index is never out of bounds, so that check is unnecessary.

/** Fills this array with NUL bytes. */
internal fun ByteArray.discard() {
  for (index in 0..<size) this[index] = 0
}

/** Fills this array with NUL characters. */
internal fun CharArray.discard() {
  for (index in 0..<size) this[index] = '\u0000'
}

/**
 * Instantiates another [CharBuffer] whose contents are equal to, but
 * **independent** from those of this one.
 *
 * To instantiate another buffer with shared contents, call
 * [duplicate][CharBuffer.duplicate] instead.
 */
private fun CharBuffer.clone(): CharBuffer {
  val clone = CharBuffer.allocate(capacity())
  if (clone.capacity() == 0) return clone
  for (index in 0..<length) clone.put(index, this[index])
  clone.position(position())
  clone.limit(limit())
  return clone
}
