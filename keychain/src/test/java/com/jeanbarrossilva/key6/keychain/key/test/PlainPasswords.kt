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

package com.jeanbarrossilva.key6.keychain.key.test

import com.jeanbarrossilva.key6.keychain.key.PlainPassword
import java.util.concurrent.ThreadLocalRandom

/** Generates a random password with default, test-specific parameters. */
internal fun PlainPassword.Companion.generate() =
  generate(
    ThreadLocalRandom.current(),
    PlainPassword.Letters.WITH_DIACRITICS,
    allowsDigits = true,
    allowsSymbols = true,
    length = 128)

/**
 * Returns a password based on this string.
 *
 * This is **unsafe** because strings are immutable, and may be or have been
 * interned, which might allow other processes to read them; this poses as a
 * security threat for passwords. As this function is only for testing purposes,
 * calling it will probably not be an issue.
 */
internal fun String.asUnsafePlainPassword() = PlainPassword.move(toCharArray())
