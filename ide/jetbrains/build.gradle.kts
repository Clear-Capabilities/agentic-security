// Gradle build for the agentic-security JetBrains plugin.
//
// Run `./gradlew buildPlugin` to produce build/distributions/*.zip — install
// via Settings → Plugins → Install Plugin from Disk.

plugins {
    id("org.jetbrains.intellij") version "1.17.3"
    kotlin("jvm") version "1.9.22"
}

group = "com.clearcapabilities"
version = "0.1.0"

repositories { mavenCentral() }

intellij {
    version.set("2023.3.6")
    type.set("IC")
    plugins.set(listOf("com.redhat.devtools.lsp4ij:0.5.0"))
}

tasks {
    patchPluginXml {
        sinceBuild.set("233")
        untilBuild.set("251.*")
    }
    buildSearchableOptions { enabled = false }
}
