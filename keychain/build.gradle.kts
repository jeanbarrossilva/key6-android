plugins {
  `java-library`
  kotlin("jvm")
}

dependencies {
  testImplementation(libs.assertk)
  testImplementation(libs.jUnit)
  testImplementation(libs.jUnitParams)
}
