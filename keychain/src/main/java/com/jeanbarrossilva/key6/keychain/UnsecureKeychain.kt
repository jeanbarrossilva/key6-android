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

import kotlin.io.encoding.Base64
import org.apache.commons.lang3.RandomStringUtils

/**
 * Keychain for testing purposes only, as it is very, *very* basic. Stored
 * passwords are hashed by being encoded to Base64, which can be easily undone
 * by some perpetrator in production.
 *
 * @property plainMainPassword Single password for accessing every key stored
 *   into the instantiated keychain, in plaintext.
 * @property unlockAttemptRate Determines the amount of times an incorrect main
 *   password will be provided by this keychain upon attempts to unlock it.
 */
class UnsecureKeychain
private constructor(
  plainMainPassword: String,
  private val unlockAttemptRate: UnlockAttemptRate
) : Keychain(plainMainPassword) {
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

  public override fun hash(plainPassword: String) =
    Base64.encode(plainPassword.toByteArray())

  override suspend fun requestPlainMainPassword(): String {
    val plainMainPassword = unhash(hashedMainPassword)
    if (currentUnlockAttemptCount++ < unlockAttemptRate.targetCount(this))
      return unlockAttemptRate.generatePlainMainPassword(plainMainPassword)
    else {
      currentUnlockAttemptCount = 0
      return plainMainPassword
    }
  }

  override fun unhash(hashedPassword: String) =
    Base64.decode(hashedPassword).toString(Charsets.UTF_8)

  companion object {
    /**
     * Instantiates an unsecure keychain with a pseudorandom main password.
     *
     * @param unlockAttemptRate Determines the amount of times an incorrect main
     *   password will be provided by this keychain upon attempts to unlock it.
     */
    @JvmStatic
    fun withRandomMainPassword(
      unlockAttemptRate: UnlockAttemptRate = UnlockAttemptRate.default
    ) =
      withPlainMainPassword(
        RandomStringUtils.insecure().next(8), unlockAttemptRate)

    /**
     * Instantiates this type of keychain with its main password specified in
     * plaintext (i.e., unhashed). For security, it will be hashed by the time
     * this function returns, and its plaintext form will become unrecoverable
     * (assuming that such form remains unreferenced after calling this
     * function).
     *
     * @param plainMainPassword Single password for accessing every key stored
     *   into the instantiated keychain, in plaintext.
     * @param unlockAttemptRate Determines the amount of times an incorrect main
     *   password will be provided by this keychain upon attempts to unlock it.
     */
    @JvmStatic
    @Throws(KeychainException::class)
    fun withPlainMainPassword(
      plainMainPassword: String,
      unlockAttemptRate: UnlockAttemptRate = UnlockAttemptRate.default
    ) = UnsecureKeychain(plainMainPassword, unlockAttemptRate)
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
enum class UnlockAttemptRate {
  /** The correct main password will be provided on the first try. */
  Lowest,

  /**
   * The correct main password will be provided after
   * ⌈[Keychain.maxUnlockAttemptCount] ÷ 2⌉ attempts to unlock with incorrect
   * passwords.
   */
  Mid,

  /**
   * The correct main password will never be provided; all passwords given when
   * requested will be incorrect.
   */
  Exceeding;

  /**
   * For non-*lowest* rates, generates a main password in plaintext that differs
   * from the correct one for the keychain; for a *lowest* rate, returns the
   * actual main password of the keychain.
   *
   * @param plainMainPassword The main password in plaintext, with the hashing
   *   applied to it undone.
   */
  internal fun generatePlainMainPassword(plainMainPassword: String): String {
    return when (this) {
      Lowest -> plainMainPassword
      Mid,
      Exceeding -> {
        var generatedPlainMainPassword: String
        do {
          generatedPlainMainPassword = RandomStringUtils.insecure().next(8)
        } while (plainMainPassword == generatedPlainMainPassword)
        generatedPlainMainPassword
      }
    }
  }

  /**
   * Returns the amount of incorrect main passwords to be provided when trying
   * to unlock the given keychain. Such amount will be respective to that of
   * this rate; for more information, refer to this rate's documentation.
   *
   * @param keychain Keychain requested to be unlocked.
   */
  internal fun targetCount(keychain: UnsecureKeychain) =
    when (this) {
      Lowest -> 0
      Mid -> keychain.maxUnlockAttemptCount / 2
      Exceeding -> keychain.maxUnlockAttemptCount + 1
    }

  companion object {
    /**
     * The default unlock attempt rate of an unsecure keychain: the *lowest*
     * rate, in which the correct main password in plaintext is provided on the
     * first attempt to unlock the keychain.
     */
    internal val default = Lowest
  }
}
