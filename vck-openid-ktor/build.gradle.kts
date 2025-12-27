import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    id("at.asitplus.gradle.vclib-conventions")
}

/* required for maven publication */
val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion


val disableAppleTargets by envExtra
kotlin {
    jvm()
    vckAndroid()
    if ("true" != disableAppleTargets) {
        val iosTargets = listOf(iosArm64(), iosSimulatorArm64(), iosX64())
        
        // Link against the Longfellow native library (needed because vck uses it)
        iosTargets.forEach { target ->
            val arch = when (target.name) {
                "iosArm64" -> "arm64"
                "iosX64" -> "x86_64-simulator"
                "iosSimulatorArm64" -> "arm64-simulator"
                else -> error("Unsupported target ${target.name}")
            }
            
            target.binaries.all {
                linkerOpts("-L${rootProject.projectDir}/vck/src/iosMain/cinterop/libs/$arch")
                linkerOpts("-llongfellow_mdoc")
                linkerOpts("-Wl,-rpath,@executable_path/Frameworks")
                
                // Copy dylib to Frameworks folder for runtime
                val binary = this
                val taskName = "copyLongfellowDylib${target.name.replaceFirstChar { it.uppercase() }}${binary.name.replaceFirstChar { it.uppercase() }}"
                val copyTask = tasks.register(taskName, Copy::class) {
                    from("${rootProject.projectDir}/vck/src/iosMain/cinterop/libs/$arch/liblongfellow_mdoc.dylib")
                    into(File(binary.outputDirectory, "Frameworks"))
                }
                binary.linkTaskProvider.configure { finalizedBy(copyTask) }
            }
        }
    }
    sourceSets {

        commonMain {
            dependencies {
                api(project(":vck-openid"))
                implementation(ktor("client-cio"))
                implementation(ktor("client-logging"))
                implementation(ktor("client-content-negotiation"))
                implementation(ktor("serialization-kotlinx-json"))
                commonImplementationDependencies()
            }
        }

        if (project.hasAndroidSdk()) {
            androidMain {
                dependencies {
                    implementation(ktor("client-android"))
                }
            }
        }

        commonTest {
            dependencies {
                implementation("at.asitplus.wallet:eupidcredential:${VcLibVersions.eupidcredential}")
                implementation("at.asitplus.wallet:mobiledrivinglicence:${VcLibVersions.mdl}")
                implementation(ktor("client-mock"))
                implementation(kotest("assertions-core"))
            }
        }

        iosTest {
            dependencies {
                implementation(ktor("client-darwin"))
            }
        }
    }
}

if ("true" != disableAppleTargets) exportXCFramework(
    "VckOpenIdKtorKmm",
    transitiveExports = true,
    static = false,
    project(":vck")
)

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/vck/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("VC-K OpenID with ktor")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model, with OpenId protocol implementations and ktor client")
                url.set("https://github.com/a-sit-plus/vck")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/vck.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/vck.git")
                    url.set("https://github.com/a-sit-plus/vck")
                }
            }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}

