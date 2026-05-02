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
 * Key6 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses.
 */

plugins {
  alias(libs.plugins.android.application) apply false
  alias(libs.plugins.spotless)
}

allprojects {
  repositories.mavenCentral()
}

subprojects {
  repositories {
    google()
    gradlePluginPortal()
  }
}

spotless {
  java {
    googleJavaFormat("1.35.0").aosp()
    target("*.java")
  }

  kotlin {
    ktfmt("0.62")
    target("*.(kt|kts)")
  }
}
