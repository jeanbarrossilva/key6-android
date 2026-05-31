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

package com.jeanbarrossilva.key6.keychain;

import java.util.random.RandomGenerator;

/** Context of plain password generation. */

// Written in Java merely because of the package-protected visibility, lacking
// in Kotlin. The downside is that the code itself is rather verbose.
public final class PlainPassword {
  /** Numbers 1–9 as characters. */
  private static final char[] digitSubset = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

  /** Letters without combining diacritics. */
  private static final char[] withoutDiacriticLetterSubset = {
    'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f', 'G', 'g', 'H',
    'h', 'I', 'i', 'J', 'j', 'K', 'k', 'L', 'l', 'M', 'm', 'N', 'n', 'O', 'o',
    'P', 'p', 'Q', 'q', 'R', 'r', 'S', 's', 'T', 't', 'U', 'u', 'V', 'v', 'W',
    'w', 'X', 'x', 'Y', 'y', 'Z', 'z'
  };

  /** Letters both with and without combining diacritics. */
  private static final char[] withDiacriticLetterSubset = {
    'A', 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ', 'a', 'à', 'á', 'â', 'ã', 'ä', 'å',
    'æ', 'B', 'b', 'C', 'Ç', 'c', 'ç', 'D', 'Ð', 'd', 'ð', 'E', 'È', 'É', 'Ê',
    'Ë', 'e', 'è', 'é', 'ê', 'ë', 'F', 'f', 'G', 'g', 'H', 'h', 'I', 'Ì', 'Í',
    'Î', 'Ï', 'i', 'ì', 'í', 'î', 'ï', 'J', 'j', 'K', 'k', 'L', 'l', 'M', 'm',
    'N', 'Ñ', 'n', 'ñ', 'O', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', 'Ø', 'o', 'ò', 'ó', 'ô',
    'õ', 'ö', 'ø', 'P', 'p', 'Q', 'q', 'R', 'r', 'S', 's', 'T', 't', 'U', 'Ù',
    'Ú', 'Û', 'Ü', 'u', 'ù', 'ú', 'û', 'ü', 'V', 'v', 'W', 'w', 'X', 'x', 'Y',
    'Ý', 'y', 'ý', 'ÿ', 'Z', 'z', 'Þ', 'þ'
  };

  /** Punctuation and other characters deemed special and printable in ASCII. */
  private static final char[] symbolSubset = {
    '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
    '}', '~'
  };

  /**
   * Selector of letters (including none) that a plain, generated password can
   * include.
   */
  public enum Letters {
    /** No letters will be included. */
    NONE,

    /** Only letters without combining diacritics may be included. */
    WITHOUT_DIACRITICS,

    /** Letters both with and without combining diacritics may be included. */
    WITH_DIACRITICS
  }

  /** This is a utility class and, thus, should not be instantiated. */
  private PlainPassword() {}

  /**
   * Generates a password in plaintext for some keychain.
   * <p>
   * <b>NOTE</b>: To ensure that other processes cannot read the generated
   * password, zero the returned array (i.e., fill it with NUL characters)
   * immediately after it has been used.
   *
   * @param rng Random number generator (RNG) for indexing the password's
   *     characters.
   * @param allowsDigits Whether the password may contain numbers.
   * @param allowsSymbols Whether the password may contain non-alphanumeric
   *     characters.
   * @param length Length of the password.
   * @return The generated plain password, or an empty string in case {@code
   *     length} ≤ 0.
   */
  static char[] generate(
      final RandomGenerator rng,
      final Letters letters,
      final boolean allowsDigits,
      final boolean allowsSymbols,
      final int length) throws NullPointerException {
    // RandomStringUtils from Apache Commons would be useful here; however,
    // passing a keychain's CSPRNG into their function halts (which makes no
    // sense to me, since such a CSPRNG is non-blocking).
    //
    // Well, let us resort to a manual implementation.

    if (rng == null)
      throw new NullPointerException(
        "Cannot generate a plain password without an RNG.");
    if (length <= 0)
      return new char[] {};
    final char[] letterSubset = switch (letters) {
      case null -> new char[]{};
      case NONE -> new char[]{};
      case WITHOUT_DIACRITICS -> withoutDiacriticLetterSubset;
      case WITH_DIACRITICS -> withDiacriticLetterSubset;
    };
    final char[] discretion = new char[
      letterSubset.length
        + (allowsDigits ? digitSubset.length : 0)
        + (allowsSymbols ? symbolSubset.length : 0)];
    if (discretion.length == 0)
      return new char[] {};
    System.arraycopy(letterSubset, 0, discretion, 0, letterSubset.length);
    if (allowsDigits)
      System.arraycopy(
        digitSubset, 0, discretion, letterSubset.length, digitSubset.length);
    if (allowsSymbols)
      System.arraycopy(
        symbolSubset,
        0,
        discretion,
        discretion.length - symbolSubset.length,
        symbolSubset.length);
    final char[] plainPassword = new char[length];
    for (int index = 0; index < length; index++)
      plainPassword[index] = discretion[rng.nextInt(discretion.length)];
    return plainPassword;
  }
}
