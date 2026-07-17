package app.zerosend.gallerysaver

import android.app.Activity
import android.content.ContentValues
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.io.FileInputStream
import java.io.IOException

@InvokeArg
class SaveArgs {
    lateinit var path: String
    lateinit var name: String
    lateinit var mime: String
}

/**
 * Copies a file the app already wrote into its own storage into the public
 * MediaStore (Pictures/Movies/Downloads, under a "ZeroSend" subfolder) so it
 * shows up in the Gallery/Files apps like anything saved by a normal app —
 * scoped storage on Android 10+ never indexes files written to a private or
 * app-scoped directory, no matter where they physically sit on disk.
 */
@TauriPlugin
class GallerySaverPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun save(invoke: Invoke) {
        var itemUri: android.net.Uri? = null
        try {
            val args = invoke.parseArgs(SaveArgs::class.java)
            val source = File(args.path)
            if (!source.exists()) {
                invoke.reject("source file does not exist: ${args.path}")
                return
            }

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                // Pre-scoped-storage devices: writing to MediaStore.Downloads isn't
                // available and legacy public-storage writes need a runtime
                // permission this plugin doesn't request. Leave the file where the
                // caller put it rather than fail the transfer outright.
                invoke.reject("gallery save requires Android 10 (API 29) or newer")
                return
            }

            val collection: android.net.Uri
            val relativeDir: String
            when {
                args.mime.startsWith("image/") -> {
                    collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                    relativeDir = Environment.DIRECTORY_PICTURES
                }
                args.mime.startsWith("video/") -> {
                    collection = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
                    relativeDir = Environment.DIRECTORY_MOVIES
                }
                else -> {
                    collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI
                    relativeDir = Environment.DIRECTORY_DOWNLOADS
                }
            }

            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, args.name)
                put(MediaStore.MediaColumns.MIME_TYPE, args.mime)
                put(MediaStore.MediaColumns.RELATIVE_PATH, "$relativeDir/ZeroSend")
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }

            val resolver = activity.contentResolver
            itemUri = resolver.insert(collection, values)
                ?: throw IOException("MediaStore insert returned no uri")

            resolver.openOutputStream(itemUri).use { out ->
                if (out == null) throw IOException("could not open output stream for $itemUri")
                FileInputStream(source).use { input -> input.copyTo(out) }
            }

            values.clear()
            values.put(MediaStore.MediaColumns.IS_PENDING, 0)
            resolver.update(itemUri, values, null, null)

            source.delete()

            val res = JSObject()
            res.put("uri", itemUri.toString())
            invoke.resolve(res)
        } catch (e: Exception) {
            // If the MediaStore row was already inserted, remove it instead of
            // leaving a permanently-pending, half-written entry behind in the
            // user's Gallery/Downloads app.
            itemUri?.let { activity.contentResolver.delete(it, null, null) }
            invoke.reject("gallery save failed: ${e.message}")
        }
    }
}
