import org.zaproxy.gradle.addon.AddOnStatus

description = "Automated authorization enforcement detection for OWASP ZAP"

zapAddOn {
    addOnName.set("Crimson Autorize")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        zapVersion.set("2.17.0")
        author.set("Renico Koen / crimsonwall.com")
        url.set("https://github.com/crimsonwall/crimsonautorize")
        extensions {
            register("org.zaproxy.addon.crimsonautorize.ExtensionCrimsonAutorize")
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">= 1.35.0 & < 2.0.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.addon.crimsonautorize.api.CrimsonAutorizeAPI")
        messages.set(file("src/main/resources/org/zaproxy/addon/crimsonautorize/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("commonlib")

    rootProject.findProject(":testutils")?.let { testImplementation(it) }
}

configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    java {
        clearSteps()
        licenseHeader(
            """
            /*
             * Crimson Autorize - Automated Authorization Testing for OWASP ZAP.
             *
             * Written by Renico Koen. Published by crimsonwall.com in 2026.
             *
             * Licensed under the Apache License, Version 2.0 (the "License");
             * you may not use this file except in compliance with the License.
             * You may obtain a copy of the License at
             *
             *     http://www.apache.org/licenses/LICENSE-2.0
             *
             * Unless required by applicable law or agreed to in writing, software
             * distributed under the License is distributed on an "AS IS" BASIS,
             * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
             * See the License for the specific language governing permissions and
             * limitations under the License.
             */
            """.trimIndent(),
        )
    }
}
