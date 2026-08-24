// The toolchain resolver lets Gradle DOWNLOAD the JDK the build asks for
// instead of failing on a machine that happens not to have it. The build
// requires JDK 21 (IntelliJ Platform 2024.2's floor); without this, a
// contributor on JDK 17 gets "No matching toolchains found" and no hint that
// provisioning was an option.
plugins { id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0" }

// Without this the project name is the DIRECTORY name, so `buildPlugin` emits
// `jetbrains-<version>.zip` — a file nobody can identify once it is downloaded.
rootProject.name = "agentic-security"
