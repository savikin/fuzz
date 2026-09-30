plugins {
    id("java")
}

group = "org.itmo.fuzzing"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

dependencies {
    implementation(project(":instrumentation"))
    implementation("org.ow2.asm:asm:9.9")
    implementation("org.jsoup:jsoup:1.18.1")
    implementation("io.vavr:vavr:1.0.1")

    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

// Runs a main class with the coverage java agent attached.
// Usage: ./gradlew runWithAgent -PmainClass=org.itmo.fuzzing.lect3.Main
tasks.register<JavaExec>("runWithAgent") {
    group = "application"
    description = "Runs the application with the coverage java agent"

    val agentJar = project(":instrumentation").tasks.named<Jar>("agentJar")
    dependsOn(agentJar)

    mainClass = (project.findProperty("mainClass") as String?) ?: "org.itmo.fuzzing.lect2.MutationCoverageFuzzer"
    classpath = sourceSets.main.get().runtimeClasspath

    jvmArgumentProviders.add(CommandLineArgumentProvider {
        listOf("-javaagent:${agentJar.get().archiveFile.get().asFile.absolutePath}")
    })
}
