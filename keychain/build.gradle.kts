plugins {
  `java-library`
  kotlin("jvm")
}

dependencies {
  implementation(libs.apache.commons.lang)
  testImplementation(libs.assertk)
  testImplementation(libs.jUnit)
  testImplementation(libs.jUnitParams)
}
