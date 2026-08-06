plugins {
  `java-library`
  kotlin("jvm")
}

dependencies {
  compileOnly(libs.jspecify) {
    because(
      "Spring Security Crypto annotates its Argon2 encoder with @Nullable."
    )
  }
  implementation(libs.apache.commons.lang)
  implementation(libs.apache.commons.logging) {
    because("Spring Security Crypto's Argon2 encoder logs.")
  }
  implementation(libs.bouncyCastle.providers)
  implementation(libs.kotlin.coroutines.core)
  implementation(libs.spring.security.crypto)
  testImplementation(libs.assertk)
  testImplementation(libs.assertk.coroutines)
  testImplementation(libs.jUnit)
  testImplementation(libs.jUnitParams)
  testImplementation(libs.kotlin.coroutines.test)
  testImplementation(libs.mockK)
}
