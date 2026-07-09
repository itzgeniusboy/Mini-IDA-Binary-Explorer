package com.example

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import java.io.File
import java.nio.ByteBuffer
import kotlinx.coroutines.*

class DecompilerService : Service() {

    private val serviceJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceJob)
    private lateinit var notificationManager: NotificationManager

    companion object {
        const val CHANNEL_ID = "decompiler_channel_id"
        const val NOTIFICATION_ID = 2001

        const val ACTION_START_DECOMPILATION = "com.example.action.START_DECOMPILATION"
        const val EXTRA_INPUT_PATH = "com.example.extra.INPUT_PATH"
        const val EXTRA_OUTPUT_PATH = "com.example.extra.OUTPUT_PATH"
        const val EXTRA_USER_URI_STRING = "com.example.extra.USER_URI_STRING"

        // Broadcast actions and extras
        const val ACTION_DECOMPILER_PROGRESS = "com.example.action.DECOMPILER_PROGRESS"
        const val EXTRA_PERCENT = "extra_percent"
        const val EXTRA_BYTES_PROCESSED = "extra_bytes_processed"
        const val EXTRA_TOTAL_BYTES = "extra_total_bytes"
        const val EXTRA_CURRENT_FUNCTION = "extra_current_function"
        const val EXTRA_STATUS = "extra_status" // "RUNNING", "COMPLETED", "FAILED"
        const val EXTRA_ERROR_MESSAGE = "extra_error_message"

        // Thread-safe global state to query progress from UI
        @Volatile var isRunning: Boolean = false
            private set
        @Volatile var lastPercent: Int = 0
            private set
        @Volatile var lastBytesProcessed: Long = 0L
            private set
        @Volatile var lastTotalBytes: Long = 0L
            private set
        @Volatile var lastCurrentFunction: String = ""
            private set
        @Volatile var lastStatus: String = "IDLE"
            private set
        @Volatile var lastError: String? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createNotificationChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent != null && intent.action == ACTION_START_DECOMPILATION) {
            val inputPath = intent.getStringExtra(EXTRA_INPUT_PATH) ?: ""
            val outputPath = intent.getStringExtra(EXTRA_OUTPUT_PATH) ?: ""
            val userUriString = intent.getStringExtra(EXTRA_USER_URI_STRING) ?: ""

            if (inputPath.isNotEmpty() && outputPath.isNotEmpty()) {
                startForeground(NOTIFICATION_ID, buildProgressNotification(0, "Initializing..."))
                isRunning = true
                lastStatus = "RUNNING"
                lastPercent = 0
                lastBytesProcessed = 0L
                lastTotalBytes = 0L
                lastCurrentFunction = "Initializing..."
                lastError = null

                // Broadcast start
                broadcastProgress(0, 0, 0, "Initializing...", "RUNNING")

                serviceScope.launch {
                    try {
                        performDecompilation(inputPath, outputPath, userUriString)
                    } catch (e: Exception) {
                        handleFailure(e.localizedMessage ?: "Unknown error")
                    }
                }
            } else {
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun performDecompilation(inputPath: String, outputPath: String, userUriString: String) {
        val inputFile = File(inputPath)
        if (!inputFile.exists()) {
            handleFailure("Input file does not exist: ${inputFile.name}")
            return
        }

        val totalBytes = inputFile.length()
        val dummyBuffer = ByteBuffer.allocate(0)
        val parser = ElfParser(dummyBuffer)

        val success = parser.decompileFileToCNative(
            inputPath = inputPath,
            outputPath = outputPath,
            callback = object : ElfParser.DecompilerProgressCallback {
                override fun onProgress(
                    bytesProcessed: Long,
                    totalBytes: Long,
                    percentage: Int,
                    currentFunction: String
                ) {
                    lastPercent = percentage
                    lastBytesProcessed = bytesProcessed
                    lastTotalBytes = totalBytes
                    lastCurrentFunction = currentFunction

                    // Update live Notification
                    notificationManager.notify(
                        NOTIFICATION_ID,
                        buildProgressNotification(
                            percentage,
                            "Decompiling: $currentFunction ($percentage%)"
                        )
                    )

                    // Broadcast progress update to UI
                    broadcastProgress(percentage, bytesProcessed, totalBytes, currentFunction, "RUNNING")
                }
            }
        )

        if (success) {
            if (userUriString.isNotEmpty()) {
                try {
                    val destUri = android.net.Uri.parse(userUriString)
                    contentResolver.openFileDescriptor(destUri, "w")?.use { pfd ->
                        java.io.FileOutputStream(pfd.fileDescriptor).use { fos ->
                            java.io.FileInputStream(File(outputPath)).use { fis ->
                                fis.channel.transferTo(0, fis.channel.size(), fos.channel)
                            }
                        }
                    }
                } catch (e: Exception) {
                    handleFailure("Decompilation succeeded, but failed to write to final destination: ${e.localizedMessage}")
                    return
                }
            }
            handleSuccess(outputPath)
        } else {
            handleFailure("JNI decompiler engine encountered a critical processing error.")
        }
    }

    private fun handleSuccess(outputPath: String) {
        isRunning = false
        lastStatus = "COMPLETED"
        lastPercent = 100
        lastCurrentFunction = "Completed successfully!"

        // Update notification to completed
        val title = "Decompilation Completed"
        val text = "C pseudocode saved to: ${File(outputPath).name}"
        val finalNotification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setOngoing(false) // Make it dismissible
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID, finalNotification)
        
        broadcastProgress(100, lastTotalBytes, lastTotalBytes, "Completed successfully!", "COMPLETED")

        // Stop foreground and make notification dismissible on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_DETACH)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(false)
        }
        stopSelf()
    }

    private fun handleFailure(errorMsg: String) {
        isRunning = false
        lastStatus = "FAILED"
        lastError = errorMsg

        // Update notification to failure
        val title = "Decompilation Failed"
        val finalNotification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(errorMsg)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setOngoing(false) // Make it dismissible
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID, finalNotification)

        broadcastProgress(lastPercent, lastBytesProcessed, lastTotalBytes, errorMsg, "FAILED", errorMsg)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_DETACH)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(false)
        }
        stopSelf()
    }

    private fun broadcastProgress(
        percent: Int,
        processed: Long,
        total: Long,
        currentFunc: String,
        status: String,
        errorMsg: String? = null
    ) {
        val intent = Intent(ACTION_DECOMPILER_PROGRESS).apply {
            putExtra(EXTRA_PERCENT, percent)
            putExtra(EXTRA_BYTES_PROCESSED, processed)
            putExtra(EXTRA_TOTAL_BYTES, total)
            putExtra(EXTRA_CURRENT_FUNCTION, currentFunc)
            putExtra(EXTRA_STATUS, status)
            if (errorMsg != null) {
                putExtra(EXTRA_ERROR_MESSAGE, errorMsg)
            }
        }
        sendBroadcast(intent)
    }

    private fun buildProgressNotification(progress: Int, subText: String): Notification {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Mini IDA Pro - C Decompiler")
            .setContentText(subText)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setProgress(100, progress, false)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Binary Decompiler Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows real-time status of high-performance ELF binary decompilation"
                enableLights(false)
                enableVibration(false)
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        serviceJob.cancel()
        isRunning = false
        super.onDestroy()
    }
}
