#!/usr/bin/env python3
"""Wires release signing into the Android project Tauri regenerates on every
`tauri android init` (src-tauri/gen/android is gitignored, so this can't be a
one-time hand-edit — see docs/CI: Tauri does not read keystore.properties on
its own, the app module's build.gradle.kts has to be told to use it).

Run after `tauri android init` and before writing keystore.properties.
Fails loudly (non-zero exit) instead of silently shipping an unsigned/
debug-signed release build if the generated file no longer matches what this
script expects to patch (e.g. after a Tauri CLI upgrade changes the template).
"""
import pathlib
import sys

GRADLE_FILE = pathlib.Path("src-tauri/gen/android/app/build.gradle.kts")

ORIGINAL = """import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {"""

PATCHED = """import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

// Release signing: only present when keystore.properties has been written
// next to this file by the "write release keystore" workflow step. Falls
// back to no signing config (Android's default debug signing) when absent,
// so a plain local `tauri android build` still works without a keystore.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
val hasReleaseSigning = keystorePropertiesFile.exists()
if (hasReleaseSigning) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {"""

RELEASE_BLOCK_ORIGINAL = """        getByName("release") {
            isMinifyEnabled = true
            proguardFiles("""

RELEASE_BLOCK_PATCHED = """        getByName("release") {
            isMinifyEnabled = true
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles("""

SIGNING_CONFIGS_ANCHOR = """    buildTypes {
        getByName("debug") {"""

SIGNING_CONFIGS_BLOCK = """    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["password"] as String
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["password"] as String
            }
        }
    }
    buildTypes {
        getByName("debug") {"""


def patch(content: str) -> str:
    for anchor in (ORIGINAL, RELEASE_BLOCK_ORIGINAL, SIGNING_CONFIGS_ANCHOR):
        if content.count(anchor) != 1:
            sys.exit(
                "patch_android_signing: expected exactly one occurrence of a known "
                f"anchor in {GRADLE_FILE}, found {content.count(anchor)}. The Tauri "
                "Android template likely changed — update this script instead of "
                "silently shipping an unsigned release build.\n"
                f"Anchor:\n{anchor}"
            )
    content = content.replace(ORIGINAL, PATCHED)
    content = content.replace(RELEASE_BLOCK_ORIGINAL, RELEASE_BLOCK_PATCHED)
    content = content.replace(SIGNING_CONFIGS_ANCHOR, SIGNING_CONFIGS_BLOCK)
    return content


def main() -> None:
    if not GRADLE_FILE.exists():
        sys.exit(f"patch_android_signing: {GRADLE_FILE} not found — run `tauri android init` first")
    content = GRADLE_FILE.read_text()
    if "hasReleaseSigning" in content:
        print("patch_android_signing: already patched, nothing to do")
        return
    GRADLE_FILE.write_text(patch(content))
    print(f"patch_android_signing: patched {GRADLE_FILE}")


if __name__ == "__main__":
    main()
