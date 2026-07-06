package com.example

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

class BinaryParsingService : Service() {

    companion object {
        const val CHANNEL_ID = "BinaryParsingChannel"
        const val NOTIFICATION_ID = 1001
        
        const val ACTION_START_PARSING = "com.example.action.START_PARSING"
        const val ACTION_STOP_PARSING = "com.example.action.STOP_PARSING"
        const val EXTRA_FILE_PATH = "com.example.extra.FILE_PATH"
    }

    // Custom single-thread executor converted to CoroutineDispatcher for heavy parsing tasks
    private val parsingExecutor = Executors.newSingleThreadExecutor()
    private val parsingDispatcher = parsingExecutor.asCoroutineDispatcher()
    private val serviceScope = CoroutineScope(parsingDispatcher + Job())
    private var parsingJob: Job? = null

    private lateinit var notificationManager: NotificationManager

    private val stopReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ACTION_STOP_PARSING) {
                stopParsingAndService()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createNotificationChannel()
        
        // Dynamically register the STOP action BroadcastReceiver
        val filter = IntentFilter(ACTION_STOP_PARSING)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(stopReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(stopReceiver, filter)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_PARSING -> {
                val filePath = intent.getStringExtra(EXTRA_FILE_PATH) ?: "unknown_binary.so"
                startForegroundNotification()
                startHeavyParsing(filePath)
            }
            ACTION_STOP_PARSING -> {
                stopParsingAndService()
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startForegroundNotification() {
        val notification = buildProgressNotification("Initializing analysis...", 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID, 
                notification, 
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startHeavyParsing(filePath: String) {
        parsingJob?.cancel()
        parsingJob = serviceScope.launch {
            try {
                // Simulating highly intense chunked ELF/SO binary parsing
                for (progress in 1..100) {
                    if (!parsingJob!!.isActive) break
                    
                    // Simulate intensive operations
                    delay(150) 
                    
                    val updateMessage = "Parsing binary: $progress% complete"
                    val notification = buildProgressNotification(updateMessage, progress)
                    notificationManager.notify(NOTIFICATION_ID, notification)
                }
                
                // Done parsing
                val doneNotification = NotificationCompat.Builder(this@BinaryParsingService, CHANNEL_ID)
                    .setContentTitle("Analysis Finished")
                    .setContentText("Successfully parsed: $filePath")
                    .setSmallIcon(android.R.drawable.stat_sys_download_done)
                    .setOngoing(false)
                    .build()
                notificationManager.notify(NOTIFICATION_ID, doneNotification)
                stopSelf()
            } catch (e: Exception) {
                e.printStackTrace()
                stopSelf()
            }
        }
    }

    private fun buildProgressNotification(contentText: String, progress: Int): Notification {
        // PendingIntent to launch stop receiver
        val stopIntent = Intent(ACTION_STOP_PARSING).setPackage(packageName)
        val stopPendingIntent = PendingIntent.getBroadcast(
            this,
            0,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // PendingIntent to open UI on notification tap
        val mainActivityIntent = Intent(this, MainActivity::class.java)
        val contentPendingIntent = PendingIntent.getActivity(
            this,
            1,
            mainActivityIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Mini IDA Analyzer")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setProgress(100, progress, false)
            .setContentIntent(contentPendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "STOP",
                stopPendingIntent
            )
            .build()
    }

    private fun stopParsingAndService() {
        parsingJob?.cancel()
        parsingExecutor.shutdownNow()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Binary Disassembly & Parsing",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows progress status when analyzing and parsing binary ELF/.so files."
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(stopReceiver)
        } catch (e: Exception) {
            // ignore
        }
        parsingJob?.cancel()
        parsingExecutor.shutdownNow()
        super.onDestroy()
    }
}
