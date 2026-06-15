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

plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.kotlin.symbolProcessor)
}

android {
  compileSdk = libs.versions.android.sdk.target.get().toInt()
  namespace = "com.jeanbarrossilva.key6"

  defaultConfig {
    applicationId = "com.jeanbarrossilva.key6"
    minSdk = libs.versions.android.sdk.min.get().toInt()
    targetSdk = compileSdk
    versionCode = 1
    versionName = "1.0"
  }
}

dependencies {
  implementation(project(":feature:locket"))
  implementation(libs.android.appcompat)
  implementation(libs.android.core)
  implementation(libs.android.navigation.fragment)
  implementation(libs.android.navigation.ui)
  implementation(libs.android.room)
  implementation(libs.material)
  ksp(libs.android.room.compiler)
  testImplementation(libs.android.test.core)
  testImplementation(libs.assertk)
  testImplementation(libs.jUnit)
  testImplementation(libs.kotlin.coroutines.test)
  testImplementation(libs.robolectric)
}
