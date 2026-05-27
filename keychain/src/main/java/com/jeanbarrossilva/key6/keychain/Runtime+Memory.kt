/*
 * Copyright © 2013 cheneym
 * https://stackoverflow.com/a/18375641/10252241
 *
 * This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
 * Unported License. For a copy of this license, refer to
 * https://creativecommons.org/licenses/by-sa/3.0.
 */

package com.jeanbarrossilva.key6.keychain

/*
 * === KEY6 CHANGES ===
 *
 * The original code is a snippet, part of a greater explanation on the
 * differences between total, maximum, free, and "free available" memory in the
 * JVM. Here, such snippet was incorporated in an extension function on the Java
 * 'Runtime' class: 'Runtime.freeAvailableMemory()'.
 */

/**
 * Calculates the amount of bytes allocatable by the JVM for this program.
 * Differs from [freeMemory][Runtime.freeMemory] in that this considers memory
 * not yet requested from the operating system.
 */
internal fun Runtime.freeAvailableMemory(): Long {
  val usedMemory = totalMemory() - freeMemory()
  return maxMemory() - usedMemory
}
