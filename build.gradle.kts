plugins {
    application
}

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

dependencies {
    implementation("io.javalin:javalin:6.7.0")
    implementation("org.slf4j:slf4j-simple:2.0.18")
    implementation("com.webauthn4j:webauthn4j-core:0.31.10.RELEASE")
    implementation("com.webauthn4j:webauthn4j-appattest:0.31.10.RELEASE")
    implementation("tools.jackson.core:jackson-databind:3.2.1")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85.2")

    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "ch.noxno.passkeydemo.Main"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
    // ./gradlew test -Dpasskey.network.tests=true also runs GoogleRootsTest
    System.getProperty("passkey.network.tests")?.let { systemProperty("passkey.network.tests", it) }
}
