plugins {
  `java-library`
  kotlin("jvm")
}

dependencies {
  implementation(libs.apache.commons.lang)
  implementation(libs.argon2)
  testImplementation(libs.assertk)
  testImplementation(libs.assertk.coroutines)
  testImplementation(libs.jUnit)
  testImplementation(libs.jUnitParams)
  testImplementation(libs.kotlin.coroutines.test)
}
