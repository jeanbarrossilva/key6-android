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

import com.android.build.api.dsl.CommonExtension

plugins {
  alias(libs.plugins.android.application) apply false
  alias(libs.plugins.android.library) apply false
  alias(libs.plugins.java)
  kotlin("jvm") version "2.3.0"
}

kotlin.jvmToolchain(21)

allprojects { repositories.mavenCentral() }

buildscript {
  dependencies {
    classpath(libs.apache.commons.text)
    classpath(libs.tomlJ)
  }
}

subprojects {
  extensions.findByType<CommonExtension>()?.apply {
    compileOptions.sourceCompatibility = JavaVersion.VERSION_17
    compileOptions.targetCompatibility = JavaVersion.VERSION_17
    defaultConfig.testInstrumentationRunner =
      "androidx.test.runner.AndroidJUnitRunner"

    buildTypes.getByName("release") {
      isMinifyEnabled = true
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
    }
  }

  repositories {
    google()
    gradlePluginPortal()
  }
}
