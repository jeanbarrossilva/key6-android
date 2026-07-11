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

import br.com.orcinus.orca.ext.reflection.java.access
import com.jeanbarrossilva.key6.keychain.key.PlainPassword
import java.security.SecureRandom
import kotlin.math.min
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.keygen.BytesKeyGenerator

// Our hasher is backed by an encoder provided by the Spring Security Crypto
// library. Such an encoder is somewhat odd (to me), and we only resort to it
// because it's the only one I found to work in Android; I've tried using the
// 'de.mkammerer:argon2-jvm' library, but it seems like it provides no
// Android-native implementation, causing it to crash at runtime.
//
// Some of the quirks of Spring's library include, but may not be limited to
//
// 1) it being by Spring, a web framework, while this part of Key6 has nothing
//    to do with the web (this isn't a practical, concerning anomaly—it's just
//    weird);
// 2) it requires that the Argon2 parameters be passed into the encoder *class*,
//    rather than to the encoder *method*. As we adapt the memory parameter to
//    the free memory available *when* hashing is performed, this means that we
//    need to reinstantiate the encoder class upon every hash (see
//    'Argon2iHasher.hash(CharArray)' and 'Argon2iHasher.initEncoder()'); and
// 3) its encoder method accepts not an array, but a sequence of characters.
//    This isn't necessarily a problem, as a 'CharSequence' isn't necessarily a
//    'String'—but it can be one, which would probably be a security loophole.
//    We take care of it by requesting a 'PlainPassword' from the caller, which
//    takes care of the potential interdependence between the password's buffer
//    and the 'CharArray' backing that buffer.

/**
 * Hasher of passwords in plaintext that uses the Argon2i function.
 *
 * This class is not thread-safe.
 *
 * @property csprng CSPRNG responsible for determining the random bytes
 *   contained in the salts of password hashes.
 * @see hash
 */
internal class Argon2iHasher(private val csprng: SecureRandom) {
  /**
   * Backing Argon2i encoder, to which hashing and matching are delegated.
   *
   * @see hash
   * @see isMatch
   */
  private lateinit var encoder: Argon2PasswordEncoder

  /** Generator of the salt of each password hash. */
  private val saltGenerator = SaltGenerator()

  /** Hash of the password passed into the last call to [hash]. */
  private lateinit var lastHash: String

  /**
   * [BytesKeyGenerator] that generates a salt for hashing some password. This
   * implementation differs from those provided by default by the library in
   * that the RNG is that of the hasher. A new instance of this class is set as
   * the private `saltGenerator` of the encoder via reflection whenever the
   * encoder gets initialized.
   *
   * @see initEncoder
   */
  private inner class SaltGenerator : BytesKeyGenerator {
    override fun getKeyLength() = SALT_LENGTH_IN_BYTES

    override fun generateKey(): ByteArray {
      val salt = newZeroedSalt()
      csprng.nextBytes(salt)
      return salt
    }
  }

  /**
   * Hashes the given password, with
   *
   * - 2 iterations;
   * - a 16-byte (128-bit) salt;
   * - a 16-byte (128-bit) hash; and
   * - a memory consumption of (potentially) 64 MiB.
   *
   * The amount of memory consumed will depend on memory availability: if more
   * than 64 MiB are available, consumption will be of 64 MiB; otherwise, 15% of
   * that free, available memory will be consumed.
   *
   * The given password **must** be zeroed after the call to this method:
   * keeping its contents may allow for other processes to read it.
   *
   * @param password The password to hash, in plaintext.
   * @see Runtime.freeAvailableMemory
   */
  fun hash(password: PlainPassword) {
    initEncoder()
    lastHash =
      checkNotNull(encoder.encode(password)) {
        "Encoder returned a null hash, even though the given password was " +
          "not null. This may be a bug in the library; to circumvent it: " +
          "find a workaround; use another library; or implement Argon2i " +
          "manually " +
          "(https://github.com/P-H-C/phc-winner-argon2/blob/f57e61e19229e23c4445b85494dbf7c07de721cb/argon2-specs.pdf)."
      }
  }

  /**
   * Determines whether the given password matches the one hashed by the last
   * call to [hash]. In case a password was never hashed, this method will
   * return `false`.
   *
   * @param password Password to check against the hashed one.
   */
  fun isMatch(password: PlainPassword): Boolean {
    // 'lastHash' being uninitialized also denotes that the encoder is
    // uninitialized, and the contrary is equally true. Therefore, going past
    // this conditional and, consequently, referencing the encoder will never
    // throw an exception.
    if (!::lastHash.isInitialized) return false

    return encoder.matches(password, lastHash)
  }

  /**
   * Initializes the encoder with the parameters specified by the [hash] method.
   *
   * Such initialization **must** occur at each call to [hash]. This is required
   * due to those parameters being passed into the constructor of the
   * encoder—rather than to its encoding method, as opposed to some other
   * libraries.
   *
   * By the time this method returns, `::encoder.isInitialized` will be `true`.
   */
  private fun initEncoder() {
    val runtime: Runtime = Runtime.getRuntime()
    val freeAvailableMemoryInKibibytes =
      runtime.freeAvailableMemory() / (1 shl 10)
    encoder =
      Argon2PasswordEncoder(
        SALT_LENGTH_IN_BYTES,
        /* hashLength = */ 16,
        /* parallelism = */ runtime.availableProcessors(),
        /* memory = */ min(
          ((freeAvailableMemoryInKibibytes) * .15).toInt(), 1 shl 16),
        /* iterations = */ 2)
    encoder::class.java.getDeclaredField("saltGenerator").access {
      set(encoder, saltGenerator)
    }
  }

  companion object {
    /**
     * Amount of bytes in the salt for producing the hash of a password, as per
     * [hash]'s documentation.
     */
    private const val SALT_LENGTH_IN_BYTES = 16

    /**
     * Instantiates an empty array to be filled with a salt for hashing a
     * password.
     */
    @JvmStatic fun newZeroedSalt() = ByteArray(SALT_LENGTH_IN_BYTES)
  }
}
