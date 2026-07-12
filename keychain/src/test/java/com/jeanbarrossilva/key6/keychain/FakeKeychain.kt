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

import com.jeanbarrossilva.key6.keychain.key.Key
import com.jeanbarrossilva.key6.keychain.key.PlainPassword
import com.jeanbarrossilva.key6.keychain.key.test.newRandomWithDirectBuffer

/**
 * In-memory keychain for testing purposes. Provides main passwords based on the
 * given attempt rate when unlocking. For a keychain that always gives out the
 * correct password, use the *lowest* rate.
 *
 * Note that, because it stores its main password in the heap, this keychain is
 * **insecure**.
 *
 * @property mainPassword Single password for accessing every key stored into
 *   the instantiated keychain, in plaintext.
 */
internal class FakeKeychain
private constructor(internal val mainPassword: PlainPassword) :
  Keychain(mainPassword) {
  /**
   * Keys stored in this keychain by a prior call to [unlockAndStore], and that
   * have not yet been removed. The string to which each of them is associated
   * is their identifier, allowing for O(1) retrievals through calls to [get].
   */
  private val storage = HashMap<String, Key>()

  /**
   * Determines the amount of times an incorrect main password will be provided
   * by this keychain upon attempts to unlock it.
   */
  private var unlockAttemptRate = UnlockAttemptRate.default

  /**
   * Amount of times attempts to unlock this keychain were made in the current
   * streak.
   *
   * This starts off as zero, may be incremented depending on the set attempt
   * rate, and will be zeroed after the incorrect main password is provided by
   * this keychain *n* times, where *n* is
   * `unlockAttemptRate.targetCount(this)`.
   *
   * @see unlockAttemptRate
   * @see UnlockAttemptRate.targetCount
   */
  private var currentUnlockAttemptCount = 0

  override suspend fun store(key: Key) {
    storage[key.id] = key
  }

  override suspend fun get(keyID: String) = storage[keyID]

  override suspend fun requestMainPassword() =
    if (currentUnlockAttemptCount <
      unlockAttemptRate.targetCount(maxUnlockAttemptCount)) {
      currentUnlockAttemptCount++
      unlockAttemptRate.generateMainPassword(this)
    } else {
      currentUnlockAttemptCount = 0

      // requestMainPassword() is called by the keychain when an unlock is
      // attempted; afterward, the password returned here is discarded
      // internally. Hence, the clone.
      mainPassword.clone()
    }

  override suspend fun remove(keyID: String) {
    storage.remove(keyID)
  }

  /**
   * Changes the unlock attempt rate of this keychain, which determines the
   * amount of times an incorrect main password will be provided by this
   * keychain upon attempts to unlock it.
   *
   * @param unlockAttemptRate The new unlock attempt rate of this keychain.
   */
  fun setUnlockAttemptRate(unlockAttemptRate: UnlockAttemptRate) {
    this.unlockAttemptRate = unlockAttemptRate
  }

  companion object {
    /** Instantiates an unsecure keychain with a random main password. */
    @JvmStatic
    fun withRandomMainPassword() =
      withMainPassword(PlainPassword.newRandomWithDirectBuffer())

    /**
     * Instantiates this type of keychain with its main password specified in
     * plaintext (i.e., unhashed). For security, it will be hashed by the time
     * this function returns, and its plaintext form will become unrecoverable
     * (assuming that such form remains unreferenced after calling this
     * function).
     *
     * @param mainPassword Single password for accessing every key stored into
     *   the instantiated keychain, in plaintext.
     */
    @JvmStatic
    @Throws(KeychainException::class)
    fun withMainPassword(mainPassword: PlainPassword) =
      FakeKeychain(mainPassword)
  }
}

/**
 * Indicates the amount of times an incorrect main password will be provided by
 * an unsecure keychain before giving the correct password out upon an attempt
 * to unlock the keychain.
 *
 * Rates other than *lowest* (the [default] rate) are more common when testing
 * keychains, where the behavior of throwing in cases of failures to unlock is
 * verified.
 *
 * @see Lowest
 * @see Keychain.IncorrectMainPasswordException
 */
internal enum class UnlockAttemptRate {
  /** The correct main password will be provided on the first try. */
  Lowest {
    override fun targetCount(max: Int) = 0
  },

  /**
   * The correct main password will be provided after
   * ⌈[Keychain.maxUnlockAttemptCount] ÷ 2⌉ attempts to unlock with incorrect
   * passwords.
   */
  Mid {
    override fun targetCount(max: Int) = max / 2
  },

  /**
   * The correct main password will never be provided; all passwords given when
   * requested will be incorrect.
   */
  Exceeding {
    override fun targetCount(max: Int) = max + 1
  };

  /**
   * For non-*lowest* rates, generates a main password in plaintext that differs
   * from the correct one for the keychain; for a *lowest* rate, returns the
   * actual main password of the keychain.
   *
   * @param keychain Keychain for which the main password will be generated.
   */
  internal fun generateMainPassword(keychain: FakeKeychain) =
    when (this) {
      Lowest -> keychain.mainPassword
      Mid,
      Exceeding ->
        keychain.generatePlainPassword(
          PlainPassword.Letters.WITH_DIACRITICS,
          allowsDigits = true,
          allowsSymbols = true,
          length = keychain.mainPassword.length / 2)
    }

  /**
   * Returns the amount of incorrect main passwords to be provided when trying
   * to unlock the given keychain. Such amount will be respective to that of
   * this rate; for more information, refer to this rate's documentation.
   *
   * @param max [Keychain.maxUnlockAttemptCount] of the keychain.
   * @return The target count *cₜ*, where *cₜ* ≥ 0 and *cₜ* ≠ [max].
   */
  internal abstract fun targetCount(max: Int): Int

  companion object {
    /**
     * The default unlock attempt rate of an unsecure keychain: the *lowest*
     * rate, in which the correct main password in plaintext is provided on the
     * first attempt to unlock the keychain.
     */
    internal val default = Lowest
  }
}
