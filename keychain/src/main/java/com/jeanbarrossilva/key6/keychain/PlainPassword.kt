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

import com.jeanbarrossilva.key6.keychain.PlainPassword.Companion.decode
import com.jeanbarrossilva.key6.keychain.PlainPassword.Companion.generate
import java.nio.Buffer
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.Random
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

/**
 * Secret for authenticating at a site, in plaintext (i.e., non-encrypted and/or
 * non-hashed).
 *
 * @property backingBuffer Buffer of characters which compose this password.
 *   Changes to it affect the contents of this password.
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
   * Selector of letters (including none) that a randomly-generated password can
   * include.
   */
  enum class Letters {
    /** No letters will be included. */
    NONE {
      override val subset = charArrayOf()
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
    val bufferDuplicate = backingBuffer.deepDuplicate()
    return PlainPassword(bufferDuplicate)
  }

  /**
   * Discards the contents of this password, preventing it from being read by
   * other processes. This method **must** be called as soon as this password
   * has been used and will not be referenced by Key6 anymore.
   */
  fun discard() {
    if (isEmpty()) return
    backingBuffer.discard()
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
      var encodedPassword = encodedPasswordBuffer.array()
      val encodedPasswordLength = encodedPasswordBuffer.limit()

      // 'encodedPassword', as-is, is padded by 16 bytes; this implies in its
      // size possibly being greater than the actual amount of UTF-16-encoded
      // characters in it. We trim the trailing padding by returning a slice
      // ranging from the start to the limit of the buffer.
      if (encodedPassword.size > encodedPasswordLength)
        encodedPassword = encodedPassword.sliceArray(0..<encodedPasswordLength)

      encodedPasswordBuffer.discard()
      encodedPassword
    }

  /**
   * Returns an array containing the characters of this password.
   *
   * @return If:
   * - this password has an array, such backing array; or
   * - this password is empty, the same empty array; or
   * - a newly-instantiated array, filled with the contents of this password.
   *
   * In the latter case, `discard(CharArray)`—rather than `discard()`—**must**
   * be called afterward: because the array was instantiated by this method and,
   * thus, **does not** back this password, discarding without passing the array
   * in will result in the password still being in the array.
   */
  internal fun asCharArray() =
    if (hasArray) backingBuffer.array()
    else if (isEmpty()) Letters.NONE.subset else newCharArray()

  /**
   * Instantiates an array containing the characters of this password. Differs
   * from [asCharArray] in that a new array is allocated *invariably*,
   * disregarding whether this password has one.
   */
  internal fun newCharArray(): CharArray {
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
    // that given array has been returned by 'asCharArray()', 'charArray' ===
    // 'toCharArray()' === 'backingBuffer.array()'); no need to proceed with the
    // O(n) array-discarding.
    if (hasArray) return

    charArray.discard()
  }

  companion object {
    /** Charset for encoding and decoding passwords: UTF-16. */
    @JvmStatic internal val charset = Charsets.UTF_16

    /** Password without contents. */
    @JvmStatic private val empty = newEmpty()

    /** Numbers 0–9 as characters. */
    @JvmStatic
    private val digits =
      charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')

    /**
     * Punctuation and other characters deemed special and printable in ASCII.
     */
    @JvmStatic
    private val symbols =
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

    /** Instantiates a password without contents. */
    internal fun newEmpty(): PlainPassword {
      val backingArray: CharBuffer = ByteBuffer.allocateDirect(0).asCharBuffer()
      return PlainPassword(backingArray)
    }

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
     * @param rng RNG for indexing the characters.
     * @param letters Selector of letters that may be included.
     * @param allowsDigits Whether numbers may be included.
     * @param allowsSymbols Whether non-alphanumeric characters may be included.
     * @param length Amount of characters to generate.
     * @return The generated password. Empty in case [length] ≤ 0.
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
      val alphabet = newGenerationAlphabet(letters, allowsDigits, allowsSymbols)
      if (alphabet.isEmpty()) return empty
      return PlainPassword(
        newPopulatedGenerationBackingBuffer(rng, alphabet, length))
    }

    /**
     * Returns an alphabet containing all subsets according to the given
     * generation configuration. These are all the characters by which a
     * password generated with such parameter set may be composed, with indexing
     * being performed by some RNG afterward.
     *
     * @param letters Selector of letters that may be included.
     * @param allowsDigits Whether numbers may be included.
     * @param allowsSymbols Whether non-alphanumeric characters may be included.
     * @see generate
     */
    @JvmStatic
    internal fun newGenerationAlphabet(
      letters: Letters,
      allowsDigits: Boolean,
      allowsSymbols: Boolean
    ): CharArray {
      // 'CharArray.plus(CharArray)' is not used here because such function
      // copies *eagerly*, without checking whether either array is or the
      // resulting union will be empty.
      val size =
        letters.subset.size +
          (if (allowsDigits) digits.size else 0) +
          (if (allowsSymbols) symbols.size else 0)
      if (size == 0) return Letters.NONE.subset
      val alphabet = CharArray(size)
      System.arraycopy(letters.subset, 0, alphabet, 0, letters.subset.size)
      if (allowsDigits)
        System.arraycopy(digits, 0, alphabet, letters.subset.size, digits.size)
      if (allowsSymbols)
        System.arraycopy(
          symbols, 0, alphabet, alphabet.size - symbols.size, symbols.size)
      return alphabet
    }

    /**
     * Allocates a new buffer, filling it with characters from the given
     * alphabet.
     *
     * @param rng RNG for indexing the alphabet.
     * @param alphabet Subsets with characters allowed to be in the buffer.
     * @param capacity Amount of characters to fill the buffer with. Because
     *   this method is only intended to be called internally, this integer is
     *   assumed to be positive.
     * @see generate
     */
    @JvmStatic
    internal fun newPopulatedGenerationBackingBuffer(
      rng: Random,
      alphabet: CharArray,
      capacity: Int
    ): CharBuffer {
      assert(capacity > 0) {
        "Capacity of buffer for generated plain password should be positive."
      }
      val backingBuffer: CharBuffer = CharBuffer.allocate(capacity)
      while (backingBuffer.hasRemaining()) backingBuffer.put(
        alphabet[rng.nextInt(alphabet.size)])
      backingBuffer.rewind()
      return backingBuffer
    }
  }
}

/**
 * Instantiates another [CharBuffer] whose contents are equal to, but
 * **independent** from those of this one.
 *
 * To instantiate another buffer with shared contents, call
 * [duplicate][CharBuffer.duplicate] instead.
 */
internal fun CharBuffer.deepDuplicate(): CharBuffer {
  val duplicate: CharBuffer = CharBuffer.allocate(capacity())
  if (duplicate.capacity() == 0) return duplicate
  for (index in 0..<length) duplicate.put(index, this[index])
  duplicate.position(position())
  duplicate.limit(limit())
  return duplicate
}

// On '*Array.discard()': yes, Kotlin provides '*Array.fill(Char)'. However,
// one of my weaknesses is that I *love* micro-optimizing, and these "fill"
// functions may perform a range check first; our indices are never out of
// bounds, so that check is unnecessary.

/** Fills this array with NUL characters. */
internal fun CharArray.discard() {
  for (index in 0..<size) this[index] = '\u0000'
}

/** Fills this array with NUL bytes. */
internal fun ByteArray.discard() {
  for (index in 0..<size) this[index] = 0
}

/**
 * This method centralizes the operations common to the discarding of any type
 * of buffer: rewinding and limit-zeroing. Discarding this buffer's backing
 * array is delegated to the [discardArray] function.
 *
 * @param discardArray Discards this buffer's backing array. Calling
 *   [array][Buffer.array] in this function *may* throw; before attempting to
 *   retrieve this buffer's backing array, ensure that it has one.
 * @see Buffer.hasArray
 */
@OptIn(ExperimentalContracts::class)
internal inline fun <BufferType> BufferType.discard(
  discardArray: () -> Unit
): BufferType where BufferType : Buffer {
  contract { callsInPlace(discardArray, InvocationKind.AT_MOST_ONCE) }
  rewind().limit(0)
  discardArray()
  return this
}

/**
 * Rewinds this buffer, zeroes its limit, and discards its backing array (if
 * any).
 *
 * @param ByteArray.discard
 */
private fun ByteBuffer.discard() = discard { if (hasArray()) array().discard() }

/**
 * Rewinds this buffer, zeroes its limit, and discards its backing array (if
 * any).
 *
 * @param CharArray.discard
 */
private fun CharBuffer.discard() = discard { if (hasArray()) array().discard() }
