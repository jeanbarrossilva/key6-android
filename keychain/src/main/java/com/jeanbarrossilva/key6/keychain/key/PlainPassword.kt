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

package com.jeanbarrossilva.key6.keychain.key

import de.xformerfhs.securesecretkeyspec.crypto.SecureSecretKeySpec
import java.nio.Buffer
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.Random
import javax.crypto.Mac
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Secret for authenticating at a site, in plaintext (i.e., non-encrypted and/or
 * non-hashed).
 *
 * @property backingBuffer Buffer of characters which compose this password.
 *   Changes to it affect the contents of this password.
 */
@JvmInline
value class PlainPassword
private constructor(private val backingBuffer: CharBuffer) : CharSequence {
  override val length: Int
    get() = backingBuffer.length

  /**
   * Selector of letters (including none) that a randomly-generated password can
   * include.
   */
  enum class Letters {
    /** No letters will be included. */
    NONE {
      override val subset = EMPTY_CHAR_ARRAY
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

  /**
   * Function for hashing a counter when generating a TOTP.
   *
   * @see generateTOTP
   */
  enum class TOTPHashFunction {
    /** Produces a 20-byte (an 160-bit) HMAC using SHA1. */
    SHA1 {
      override val algorithmName = "HmacSHA1"
    },

    /** Produces a 32-byte (256-bit) HMAC using SHA256. */
    SHA256 {
      override val algorithmName = "HmacSHA256"
    },

    /** Produces a 64-byte (512-bit) HMAC using SHA512. */
    SHA512 {
      override val algorithmName = "HmacSHA512"
    };

    /**
     * Name of the HMAC algorithm represented by this entry as per the
     * [Java Security Standard Algorithm Names](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html).
     */
    internal abstract val algorithmName: String
  }

  /**
   * Exception thrown upon trying to generate a TOTP because of an unsatisfied
   * requirement as per the HOTP and the TOTP RFCs. For the official references,
   * see the sections below of these RFCs:
   *
   * - **HOTP**: [§ 4. Algorithm Requirements](https://www.rfc-editor.org/info/rfc4226/#section-4)
   *   and
   *   [§ 7. Security Requirements](https://www.rfc-editor.org/info/rfc4226/#section-7);
   * - **TOTP**: [§ 3. Algorithm Requirements](https://www.rfc-editor.org/info/rfc6238/#section-3).
   *
   * @param message Description of why this exception was thrown.
   * @see generateTOTP
   */
  sealed class TOTPException(message: String) :
    IllegalArgumentException(message) {
    /**
     * Thrown if the TOTP is requested to contain less than 6 or more than 8
     * digits. This constraint exists due to TOTPs whose length is too short
     * being considerably insecure; conversely, ones with a greater amount of
     * digits would often be prefixed by zeroes, given that the HOTP algorithm
     * outputs integers containing as few as 31 bits.
     *
     * @property length The amount of digits with which the TOTP was attempted
     *   to be generated, lesser than 6 or greater than 8.
     * @see HOTP_LENGTH_RECOMMENDATION
     */
    class LowEntropy internal constructor(val length: Int) :
      TOTPException("TOTP length should be in the [6, 8] range (was $length).")

    /**
     * Thrown if the current time is lesser than zero; this denotes that such
     * time is before the Unix epoch (Jan 1, 1970, 00:00), which is prohibited.
     *
     * @property currentTime Negative time passed into the TOTP generator.
     */
    class PreUnixEpochTime internal constructor(val currentTime: Duration) :
      TOTPException("Current time cannot be before the Unix epoch.")

    /**
     * Thrown if the seed passed into the [generateTOTP] function has less than
     * 128 bits (16 bytes); such a seed is deemed too short in the RFC and is
     * prohibited as input to the algorithm.
     *
     * @property size Actual size of the given seed.
     */
    class ShortSeed internal constructor(val size: Int) :
      TOTPException(
        "TOTP seed must contain at least 16 bytes (128 bits); given one had " +
          "$size.")
  }

  override fun get(index: Int) = backingBuffer[index]

  override fun subSequence(startIndex: Int, endIndex: Int) =
    backingBuffer.subSequence(startIndex, endIndex)

  override fun toString() = backingBuffer.toString()

  /**
   * Returns a password whose contents equal those of this one, backed by an
   * independent buffer: changes to the contents of this password **will not**
   * affect those of the returned clone, and vice versa.
   *
   * This operation is **unsafe** because this password gets duplicated, and its
   * contents are not moved to its clone.
   */
  fun cloneUnsafe(): PlainPassword {
    if (isEmpty()) {
      return EMPTY
    }
    val bufferDuplicate = backingBuffer.deepDuplicate()
    return PlainPassword(bufferDuplicate)
  }

  /**
   * Discards the contents of this password, preventing it from being read by
   * other processes. This method **must** be called as soon as this password
   * has been used and will not be referenced by Key6 anymore.
   */
  fun discard() {
    if (isEmpty()) {
      return
    }
    backingBuffer.discard()
  }

  /**
   * Returns an array containing the bytes of the UTF-16-encoded contents of
   * this password.
   *
   * This method is the opposite of [decodeAndMove], which takes in bytes of
   * some UTF-16-encoded password; such symmetry denotes that
   * `Companion.decodeAndMove(encode()) == this`.
   */
  internal fun encode() =
    // 'Charset.encode(CharBuffer)' may search for the UTF-16 encoder, but there
    // will be no character to encode in case this password is empty. We avoid
    // that unnecessary work here.
    if (isEmpty()) {
      EMPTY_BYTE_ARRAY
    } else {
      val encodedPasswordBuffer = CHARSET.encode(backingBuffer)
      backingBuffer.rewind()
      var encodedPassword: ByteArray = encodedPasswordBuffer.array()
      val encodedPasswordLength = encodedPasswordBuffer.limit()

      // 'encodedPassword', as-is, is padded by 16 bytes; this implies in its
      // size possibly being greater than the actual amount of UTF-16-encoded
      // characters in it. We trim the trailing padding by returning a slice
      // ranging from the start to the limit of the buffer.
      if (encodedPassword.size > encodedPasswordLength) {
        encodedPassword = encodedPassword.sliceArray(0..<encodedPasswordLength)
      }

      encodedPasswordBuffer.discard()
      encodedPassword
    }

  /**
   * Returns an array containing the characters of this password.
   *
   * @return If this password is empty, the same empty array; else a
   *   newly-instantiated array, filled with the contents of this password.
   *
   * In the latter case, the array **must** be discarded after used: it was
   * instantiated by this method and, thus, **does not** back this password.
   *
   * @see CharArray.discard
   */
  internal fun asCharArray() =
    if (isEmpty()) {
      EMPTY_CHAR_ARRAY
    } else {
      newCharArray()
    }

  companion object {
    /**
     * Amount of bytes for representing a character in the password [CHARSET].
     */
    private const val CHARSET_DECODED_CHARACTER_SIZE_IN_BYTES = 2

    /** Numbers 0–9 as characters. */
    @JvmStatic
    private val DIGITS =
      charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')

    /** An array without bytes. */
    @JvmStatic private val EMPTY_BYTE_ARRAY = byteArrayOf()

    /** An array without characters. */
    @JvmStatic private val EMPTY_CHAR_ARRAY = charArrayOf()

    /**
     * Punctuation and other characters deemed special and printable in ASCII.
     */
    @JvmStatic
    private val SYMBOLS =
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
     * Pre-computed powers of 10 for truncating the amount of digits in some
     * HOTP being generated, from 10⁶ up to 10⁸. The remainder of the division
     * between such HOTP and the desired length *n* equals to the HOTP with its
     * last *n* digits, where 6 ≤ *n* ≤ 8, with the integer of this array at
     * *n* - `HOTP_LENGTH_RECOMMENDATION.last` +
     * `HOTP_TRUNCATION_MODULI.lastIndex` being the modulus.
     *
     * @see generateTOTP
     * @see HOTP_LENGTH_RECOMMENDATION
     */
    @JvmStatic
    private val HOTP_TRUNCATION_MODULI =
      intArrayOf(1_000_000, 10_000_000, 100_000_000)

    /**
     * Minimum amount of bytes that a key passed as input into [generateTOTP] is
     * required to contain, as per the TOTP RFC.
     */
    internal const val TOTP_MIN_KEY_SIZE_IN_BYTES = 16

    /** Password without contents. */
    @JvmStatic internal val EMPTY = PlainPassword(newEmptyBackingBuffer(0))

    /** Charset for encoding and decoding passwords: UTF-16. */
    @JvmStatic internal val CHARSET = Charsets.UTF_16

    /**
     * Lengths recommended by the HOTP RFC for a generated HOTP (see
     * [§ 5.3](https://www.rfc-editor.org/info/rfc4226/#section-5.3)).
     * Attempting to generate a TOTP with a length outside of this range in Key6
     * will throw an exception.
     *
     * @see generateTOTP
     * @see TOTPException.LowEntropy
     */
    @JvmStatic val HOTP_LENGTH_RECOMMENDATION = 6..8

    /**
     * Instantiates a plain password with the given contents. Each character in
     * the array is transferred to the password, such that the array will
     * contain only NULs after this function returns.
     *
     * @param contents Characters of the password.
     * @return A password with the specified contents.
     */
    @JvmStatic
    internal fun move(contents: CharArray): PlainPassword =
      if (contents.isEmpty()) {
        EMPTY
      } else {
        val backingBuffer = newEmptyBackingBuffer(contents.size)
        for (index in contents.indices) {
          backingBuffer.put(contents[index])
          contents[index] = '\u0000'
        }
        backingBuffer.rewind()
        PlainPassword(backingBuffer)
      }

    /**
     * Instantiates a password from an array of bytes, containing the bytes
     * resulted from encoding the characters of the original password. Each byte
     * is transferred from the array to the password, with the array being
     * zeroed by the time this function returns.
     *
     * @param encodedPassword The UTF-16-encoded password to decode.
     * @see encode
     */
    @JvmStatic
    internal fun decodeAndMove(encodedPassword: ByteArray) =
      if (encodedPassword.isEmpty()) {
        EMPTY
      } else {
        val encodedPasswordBuffer: ByteBuffer =
          ByteBuffer.allocateDirect(encodedPassword.size)
        for (index in encodedPassword.indices) {
          encodedPasswordBuffer.put(encodedPassword[index])
          encodedPassword[index] = 0
        }
        encodedPasswordBuffer.rewind()
        val backingBuffer: CharBuffer = CHARSET.decode(encodedPasswordBuffer)
        PlainPassword(backingBuffer)
      }

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
      if (length <= 0) {
        return EMPTY
      }

      // 'CharArray.plus(CharArray)' is not used here because such function
      // copies *eagerly*, without checking whether either array is or the
      // resulting union will be empty.
      val size =
        letters.subset.size +
          (if (allowsDigits) DIGITS.size else 0) +
          (if (allowsSymbols) SYMBOLS.size else 0)
      if (size == 0) {
        return EMPTY
      }
      val alphabet = CharArray(size)
      System.arraycopy(
        /* src = */ letters.subset,
        /* srcPos = */ 0,
        /* dest = */ alphabet,
        /* destPos = */ 0,
        /* length = */ letters.subset.size)
      if (allowsDigits) {
        System.arraycopy(
          /* src = */ DIGITS,
          /* srcPos = */ 0,
          /* dest = */ alphabet,
          /* destPos = */ letters.subset.size,
          /* length = */ DIGITS.size)
      }
      if (allowsSymbols) {
        System.arraycopy(
          /* src = */ SYMBOLS,
          /* srcPos = */ 0,
          /* dest = */ alphabet,
          /* destPos = */ alphabet.size - SYMBOLS.size,
          /* length = */ SYMBOLS.size)
      }
      val backingBuffer = newEmptyBackingBuffer(length)
      while (backingBuffer.hasRemaining()) {
        backingBuffer.put(alphabet[rng.nextInt(alphabet.size)])
      }
      backingBuffer.rewind()
      return PlainPassword(backingBuffer)
    }

    /**
     * Generates a time-based one-time password (TOTP).
     *
     * A TOTP is a temporary secret, described in
     * [RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)](https://www.rfc-editor.org/info/rfc6238/).
     * Multifactor authentication (MFA) with a TOTP may be adopted by a site
     * alongside a regular, plain password defined by the user; this provides an
     * extra layer of security, allowing for the user to authenticate its
     * identity. Such authentication tends to be secure because, often,
     * generator programs are NIST-compliant, and the user owns the instance of
     * the generator program (here, Key6) by which the TOTP was generated.
     *
     * The usual user-facing flow until reaching the point of generating a TOTP
     * is the following:
     *
     * 1) The user signs into the site without MFA;
     * 2) the site prompts them to increase the security of their account by
     *    enabling MFA;
     * 3) the user agrees to do so; and
     * 3) the site displays either a seed in plaintext, commonly encoded in
     *    Base32 with trailing padding omitted, or a QR code representing that
     *    seed.
     *
     * Such seed is public, and will be that shared with Key6 by being passed
     * into the [seed] parameter. This function will, then, generate a TOTP with
     * the specified length, valid for the amount of time in the [step] since
     * the current time; past this duration plus the validation window of the
     * site, the TOTP expires, and, once MFA is enabled, a new one must be
     * generated for the user to authenticate.
     *
     * ## References
     *
     * - M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *TOTP:
     *   Time-based one-time password algorithm (RFC 6238)*. Internet
     *   Engineering Task Force. https://doi.org/10.17487/RFC6238;
     * - M'Raihi, D., Bellaware, M., Hoornaert, F., Naccache, D., & Ranen, O.
     *   (2005). *HOTP: An HMAC-Based One-Time Password Algorithm*. Internet
     *   Engineering Task Force.
     * - Wolford, B. (2026). *What is HOTP? A guide to HMAC-based one-time
     *   passwords*. Proton. https://proton.me/blog/hotp.
     *
     * @param seed Bytes known by Key6 and the site at which the user may
     *   authenticate, produced by such site. As per the RFC, this seed should
     *   have been generated randomly and must contain at least 16 bytes (128
     *   bits). Failure to satisfy this minimum will result in an exception
     *   being thrown.
     * @param currentTime Time passed since the last Unix epoch, from which the
     *   step will be counted. Zero denotes Jan 1, 1970, 00:00; times prior to
     *   that (i.e., negative) are prohibited.
     * @param step Duration of the validity of the TOTP, starting from the
     *   current time.
     * @param hashFunction Function that hashes the counter derived from the
     *   given current time and step.
     * @param length Amount of digits in the TOTP, where each digit is in [[0,
     *   9]]. Due to the low entropy that would result from lengths past either
     *   ends of the range, this method treats the RFC's recommendation on the
     *   length as a requirement: 6 ≤ [length] ≤ 8, defaulting to 6.
     */
    @JvmStatic
    @Throws(TOTPException::class)
    internal fun generateTOTP(
      seed: ByteArray,
      currentTime: Duration = System.currentTimeMillis().milliseconds,
      step: Duration = 30.seconds,
      hashFunction: TOTPHashFunction = TOTPHashFunction.SHA1,
      length: Int = HOTP_LENGTH_RECOMMENDATION.first
    ): PlainPassword {
      if (seed.size < TOTP_MIN_KEY_SIZE_IN_BYTES) {
        throw TOTPException.ShortSeed(seed.size)
      }
      if (currentTime.isNegative()) {
        throw TOTPException.PreUnixEpochTime(currentTime)
      }
      if (length !in HOTP_LENGTH_RECOMMENDATION) {
        throw TOTPException.LowEntropy(length)
      }
      val counterAsLong = currentTime.inWholeSeconds / step.inWholeSeconds
      val counterAsByteArray = ByteArray(Byte.SIZE_BITS)
      for (index in counterAsByteArray.indices) {
        counterAsByteArray[index] =
          (counterAsLong ushr (Byte.SIZE_BITS * (Byte.SIZE_BITS - 1 - index)))
            .toByte()
      }

      // This is where the implementation of the HOTP algorithm begins. The TOTP
      // algorithm simply imposes a constraint as to what the HOTP counter
      // parameter is: the amount of steps that the interval between the Unix
      // epoch and the current time comprises, floored.

      val hmac: Mac = Mac.getInstance(hashFunction.algorithmName)
      val seedSpec = SecureSecretKeySpec(seed, "RAW")
      hmac.init(seedSpec)
      val hash: ByteArray = hmac.doFinal(counterAsByteArray)
      counterAsByteArray.discard()
      seedSpec.destroy()
      val truncationStartOffset =
        hash.last().toInt() and
          // 00000F (hexadecimal) = 00001111 (binary) = 15 (decimal). The offset
          // being the last nibble of the last byte of the to-be-truncated TOTP
          // restricts it to [0, 15].
          0x0f
      var totpAsInt =
        hash[truncationStartOffset].toInt() and Byte.MAX_VALUE.toInt()
      for (offset in (truncationStartOffset + 1)..(truncationStartOffset + 3)) {
        totpAsInt =
          (totpAsInt shl Byte.SIZE_BITS) or (hash[offset].toInt() and 0xff)
      }
      totpAsInt %=
        HOTP_TRUNCATION_MODULI[
          length - HOTP_LENGTH_RECOMMENDATION.last +
            HOTP_TRUNCATION_MODULI.lastIndex]
      val backingBuffer = newEmptyBackingBuffer(length)
      repeat(length) {
        backingBuffer.put(length - it - 1, (totpAsInt % 10).digitToChar())
        totpAsInt /= 10
      }
      backingBuffer.rewind()
      return PlainPassword(backingBuffer)
    }

    /**
     * Instantiates a buffer into which the given amount of characters can be
     * put. The returned buffer is a direct one: the JVM will, as much as
     * possible, avoid copying its contents to intermediate buffers, lessening
     * the probability of these contents being readable by other processes.
     *
     * @param capacity Total amount of characters that can be put into the
     *   buffer.
     */
    internal fun newEmptyBackingBuffer(capacity: Int): CharBuffer =
      ByteBuffer.allocateDirect(
          capacity * CHARSET_DECODED_CHARACTER_SIZE_IN_BYTES)
        .asCharBuffer()
  }
}

/** Instantiates an array containing the characters of this sequence. */
internal fun CharSequence.newCharArray(): CharArray {
  val charArray = CharArray(length)
  for (index in charArray.indices) {
    charArray[index] = this[index]
  }
  return charArray
}

/**
 * Instantiates another [CharBuffer] whose contents are equal to, but
 * **independent** from those of this one.
 *
 * To instantiate another buffer with shared contents, call
 * [duplicate][CharBuffer.duplicate] instead.
 */
internal fun CharBuffer.deepDuplicate(): CharBuffer {
  val deepDuplicate: CharBuffer =
    if (hasArray()) {
      CharBuffer.allocate(capacity())
    } else {
      PlainPassword.newEmptyBackingBuffer(capacity())
    }
  if (deepDuplicate.capacity() == 0) {
    return deepDuplicate
  }
  for ((index, element) in withIndex()) {
    deepDuplicate.put(index, element)
  }
  deepDuplicate.position(position())
  deepDuplicate.limit(limit())
  return deepDuplicate
}

// On '*Array.discard()': yes, Kotlin provides '*Array.fill(Char)'. However,
// one of my weaknesses is that I *love* micro-optimizing, and these "fill"
// functions may perform a range check first; our indices are never out of
// bounds, so that check is unnecessary.

/** Fills this array with NUL characters. */
internal fun CharArray.discard() {
  for (index in indices) {
    this[index] = '\u0000'
  }
}

/** Fills this array with NUL bytes. */
internal fun ByteArray.discard() {
  for (index in indices) {
    this[index] = 0
  }
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
private fun ByteBuffer.discard() = discard {
  if (hasArray()) {
    array().discard()
  }
}

/**
 * Rewinds this buffer, zeroes its limit, and discards its backing array (if
 * any).
 *
 * @param CharArray.discard
 */
private fun CharBuffer.discard() = discard {
  if (hasArray()) {
    array().discard()
  }
}
