// Gradle build for the agentic-security JetBrains plugin.
//
// Run `./gradlew buildPlugin` to produce build/distributions/*.zip — install
// via Settings → Plugins → Install Plugin from Disk.
//
// ── Why this file was rewritten ──────────────────────────────────────────────
//
// It previously used `org.jetbrains.intellij` 1.17.4 — the SUPERSEDED major of
// the IntelliJ Gradle plugin — against IDE 2023.3.6 (IC-233), and pinned CI to
// Gradle 8.10 because 1.17.4 cannot be applied by Gradle 9 at all
// (`Type DefaultArtifactPublicationSet not present`). That pin bought a build
// that still did not work: LSP4IJ dropped IC-233 support at 0.18.0, so
// `com.redhat.devtools.lsp4ij:0.19.4` was never compatible with the platform it
// was being resolved against, and every CI run failed with
//
//     Plugin 'com.redhat.devtools.lsp4ij:0.19.4' is not compatible to: IC-233.15026.9
//
// Two ways out: hold IC-233 and go back to LSP4IJ 0.17.0 (the last release that
// supports it, from before the 2.x toolchain existed), or move the floor to the
// oldest platform current LSP4IJ actually supports. This takes the second. The
// first freezes a distribution on a two-year-old dependency to keep a
// compatibility claim nobody has exercised.
//
// ── Consequence, stated plainly ──────────────────────────────────────────────
//
// `sinceBuild` moves 233 → 242. IntelliJ 2023.3 and 2024.1 are no longer
// supported by this plugin. That is not a preference — it is LSP4IJ's floor, and
// this plugin is a thin wrapper around LSP4IJ. There is no version of this
// plugin that supports 2023.3 AND a maintained LSP4IJ.

plugins {
    id("org.jetbrains.intellij.platform") version "2.18.1"
    kotlin("jvm") version "2.1.0"
}

group = "com.clearcapabilities"
version = "0.1.0"

repositories {
    mavenCentral()
    // The 2.x plugin resolves IDEs and marketplace plugins through its own
    // repository set; mavenCentral alone cannot see either.
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform {
        // 2024.2 is the oldest platform current LSP4IJ supports, so it is the
        // oldest one this plugin can be built against.
        intellijIdeaCommunity("2024.2.5")
        plugin("com.redhat.devtools.lsp4ij:0.20.1")
    }
}

// JDK 21, not 17. IntelliJ Platform 2024.2 requires Java 21 — building it
// against 17 compiles and produces a zip, and `verifyPluginProjectConfiguration`
// is the only thing that says so ("sourceCompatibility is set to '17', but
// IntelliJ Platform '2024.2.5' requires Java '21'"). The first draft of this
// migration shipped 17 for exactly that reason: the build was green.
kotlin { jvmToolchain(21) }

intellijPlatform {
    buildSearchableOptions = false
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "242"
            // Deliberately OPEN. The default in the 2.x plugin is to cap at the
            // build being compiled against (`242.*`), which would be narrower
            // than what this plugin shipped with before. The previous explicit
            // cap of `251.*` had already gone stale — 2025.2 exists — and a
            // stale cap presents to the user as "plugin incompatible" on an IDE
            // that would have worked. This plugin touches three stable LSP4IJ /
            // platform types (LanguageServerFactory, StreamConnectionProvider,
            // ProcessStreamConnectionProvider), so there is no version we know
            // it breaks on; declaring one we cannot test would be a guess in the
            // direction that costs users.
            untilBuild = provider { null }
        }
    }
}
