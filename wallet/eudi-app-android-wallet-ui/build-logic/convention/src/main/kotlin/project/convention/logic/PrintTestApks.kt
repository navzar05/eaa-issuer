/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package project.convention.logic

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.api.variant.BuiltArtifactsLoader
import com.android.build.api.variant.HasAndroidTest
import org.gradle.api.DefaultTask
import org.gradle.api.Project
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import java.io.File

internal fun Project.configurePrintApksTask(extension: AndroidComponentsExtension<*, *, *>) {
    extension.onVariants { variant ->
        if (variant is HasAndroidTest) {
            val loader = variant.artifacts.getBuiltArtifactsLoader()
            val artifact = variant.androidTest?.artifacts?.get(SingleArtifact.APK)
            val javaSources = variant.androidTest?.sources?.java?.all
            val kotlinSources = variant.androidTest?.sources?.kotlin?.all

            val testSources = if (javaSources != null && kotlinSources != null) {
                javaSources.zip(kotlinSources) { javaDirs, kotlinDirs ->
                    javaDirs + kotlinDirs
                }
            } else javaSources ?: kotlinSources

            if (artifact != null && testSources != null) {
                tasks.register(
                    "${variant.name}PrintTestApk",
                    PrintApkLocationTask::class.java
                ) {
                    apkFolder.set(artifact)
                    builtArtifactsLoader.set(loader)
                    variantName.set(variant.name)
                    sources.set(testSources)
                }
            }
        }
    }
}

internal abstract class PrintApkLocationTask : DefaultTask() {
    @get:InputDirectory
    abstract val apkFolder: DirectoryProperty

    @get:InputFiles
    abstract val sources: ListProperty<Directory>

    @get:Internal
    abstract val builtArtifactsLoader: Property<BuiltArtifactsLoader>

    @get:Input
    abstract val variantName: Property<String>

    @TaskAction
    fun taskAction() {
        val hasFiles = sources.orNull?.any { directory ->
            directory.asFileTree.files.any {
                it.isFile && it.parentFile.path.contains("build${File.separator}generated").not()
            }
        } ?: throw RuntimeException("Cannot check androidTest sources")

        if (!hasFiles) {
            return
        }

        val builtArtifacts = builtArtifactsLoader.get().load(apkFolder.get())
            ?: throw RuntimeException("Cannot load APKs")
        if (builtArtifacts.elements.size != 1)
            throw RuntimeException("Expected one APK !")
        val apk = File(builtArtifacts.elements.single().outputFile).toPath()
        println(apk)
    }
}