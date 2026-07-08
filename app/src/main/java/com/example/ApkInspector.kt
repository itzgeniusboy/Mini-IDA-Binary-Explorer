package com.example

import android.content.Context
import android.net.Uri
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream

object ApkInspector {

    data class ApkNativeLib(
        val abi: String,
        val entryName: String,
        val libraryName: String,
        val sizeBytes: Long
    )

    data class InspectionResult(
        val isValidApk: Boolean,
        val nativeLibs: List<ApkNativeLib>,
        val errorMessage: String? = null
    )

    /**
     * Inspects an APK file via Uri, finding all native libraries and checking its validity.
     */
    fun inspectApk(context: Context, apkUri: Uri): InspectionResult {
        val nativeLibs = mutableListOf<ApkNativeLib>()
        var hasAndroidManifest = false
        var hasMetaInf = false

        try {
            context.contentResolver.openInputStream(apkUri)?.use { inputStream ->
                ZipInputStream(BufferedInputStream(inputStream)).use { zipInputStream ->
                    var entry = zipInputStream.nextEntry
                    while (entry != null) {
                        val name = entry.name
                        
                        if (name == "AndroidManifest.xml" || name.endsWith("AndroidManifest.xml")) {
                            hasAndroidManifest = true
                        } else if (name.startsWith("META-INF/")) {
                            hasMetaInf = true
                        }

                        // Match lib/<abi>/*.so
                        val parts = name.split("/")
                        if (parts.size == 3 && parts[0] == "lib" && parts[2].endsWith(".so")) {
                            val abi = parts[1]
                            val libName = parts[2]
                            val size = entry.size // Note: size might be -1 if not specified in local file header
                            nativeLibs.add(ApkNativeLib(abi, name, libName, size))
                        }
                        
                        zipInputStream.closeEntry()
                        entry = zipInputStream.nextEntry
                    }
                }
            }

            val isValid = hasAndroidManifest || hasMetaInf
            val errorMsg = if (!isValid) "Not a valid APK: missing AndroidManifest.xml or META-INF/" else null
            
            return InspectionResult(
                isValidApk = isValid,
                nativeLibs = nativeLibs,
                errorMessage = errorMsg
            )
        } catch (e: Exception) {
            e.printStackTrace()
            return InspectionResult(
                isValidApk = false,
                nativeLibs = emptyList(),
                errorMessage = "Error parsing APK: ${e.localizedMessage}"
            )
        }
    }

    /**
     * Generates a stable and unique ID for an APK based on its content (MD5 hash).
     */
    fun getApkFileId(context: Context, uri: Uri): String {
        return try {
            val digest = MessageDigest.getInstance("MD5")
            context.contentResolver.openInputStream(uri)?.use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            val md5Bytes = digest.digest()
            md5Bytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            val size = try {
                context.contentResolver.openFileDescriptor(uri, "r")?.use { pfd -> pfd.statSize } ?: 0L
            } catch (ex: Exception) {
                0L
            }
            val cleanName = (uri.lastPathSegment ?: "apk").replace("[^a-zA-Z0-9]".toRegex(), "_")
            "fallback_${cleanName}_$size"
        }
    }

    /**
     * Extracts a specific native library entry from the APK to the app-private storage.
     * Path: context.filesDir/extracted_libs/<file_id_of_apk>/<abi>_<libname>.so
     * Returns the extracted File, or null if failed.
     */
    fun extractLibrary(
        context: Context,
        apkUri: Uri,
        fileId: String,
        lib: ApkNativeLib,
        onProgress: (Float) -> Unit = {}
    ): File? {
        val destDir = File(context.filesDir, "extracted_libs/$fileId")
        if (!destDir.exists()) {
            destDir.mkdirs()
        }

        val destFile = File(destDir, "${lib.abi}_${lib.libraryName}")
        
        try {
            context.contentResolver.openInputStream(apkUri)?.use { inputStream ->
                ZipInputStream(BufferedInputStream(inputStream)).use { zipInputStream ->
                    var entry = zipInputStream.nextEntry
                    while (entry != null) {
                        if (entry.name == lib.entryName) {
                            // Found the target library, stream it to destFile
                            FileOutputStream(destFile).use { fos ->
                                BufferedOutputStream(fos).use { bos ->
                                    val buffer = ByteArray(16384)
                                    var bytesRead: Int
                                    var totalCopied = 0L
                                    val totalSize = if (lib.sizeBytes > 0) lib.sizeBytes else entry.size
                                    
                                    while (zipInputStream.read(buffer).also { bytesRead = it } != -1) {
                                        bos.write(buffer, 0, bytesRead)
                                        totalCopied += bytesRead
                                        if (totalSize > 0) {
                                            val progress = totalCopied.toFloat() / totalSize
                                            onProgress(progress.coerceIn(0f, 1f))
                                        }
                                    }
                                    bos.flush()
                                }
                            }
                            zipInputStream.closeEntry()
                            return destFile
                        }
                        zipInputStream.closeEntry()
                        entry = zipInputStream.nextEntry
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            if (destFile.exists()) {
                destFile.delete()
            }
        }
        return null
    }

    /**
     * Cleans up the extracted_libs cache directory.
     * If maxAgeDays is provided, deletes files older than N days.
     */
    fun clearCache(context: Context, maxAgeDays: Int = 0) {
        val cacheDir = File(context.filesDir, "extracted_libs")
        if (!cacheDir.exists() || !cacheDir.isDirectory) return

        val now = System.currentTimeMillis()
        val maxAgeMs = maxAgeDays.toLong() * 24 * 60 * 60 * 1000

        try {
            if (maxAgeDays <= 0) {
                // Delete everything
                cacheDir.deleteRecursively()
            } else {
                // Delete files older than maxAgeDays
                deleteOldFiles(cacheDir, now, maxAgeMs)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun deleteOldFiles(file: File, now: Long, maxAgeMs: Long) {
        if (file.isDirectory) {
            val children = file.listFiles() ?: return
            for (child in children) {
                deleteOldFiles(child, now, maxAgeMs)
            }
            // After deleting children, if directory is empty, delete it too
            if (file.listFiles()?.isEmpty() == true) {
                file.delete()
            }
        } else {
            if (now - file.lastModified() > maxAgeMs) {
                file.delete()
            }
        }
    }
}
