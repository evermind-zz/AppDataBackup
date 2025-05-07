package com.github.evermindzz.appdatabackup;

import android.util.Log;

import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Wrapper for Android Log methods, adding timestamps and optional gzipped file logging.
 */
public class Logger {
    private static final String TAG = Logger.class.getSimpleName();
    private static final SimpleDateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
    private static boolean logToFile = false;
    private static BufferedWriter fileWriter = null;
    private static FileOutputStream fileOutputStream = null;
    private static GzipCompressorOutputStream gzipOutputStream = null;

    /**
     * Log debug message.
     */
    public static void d(String message) {
        String logEntry = TIMESTAMP_FORMAT.format(new Date()) + " D/" + TAG + ": " + message;
        Log.d(TAG, message);
        writeToFile(logEntry);
    }

    /**
     * Log warning message.
     */
    public static void w(String message) {
        String logEntry = TIMESTAMP_FORMAT.format(new Date()) + " W/" + TAG + ": " + message;
        Log.w(TAG, message);
        writeToFile(logEntry);
    }

    /**
     * Log error message.
     */
    public static void e(String message) {
        String logEntry = TIMESTAMP_FORMAT.format(new Date()) + " E/" + TAG + ": " + message;
        Log.e(TAG, message);
        writeToFile(logEntry);
    }

    /**
     * Log error with throwable.
     */
    public static void e(String message, Throwable t) {
        String logEntry = TIMESTAMP_FORMAT.format(new Date()) + " E/" + TAG + ": " + message + ": " + t.getMessage();
        Log.e(TAG, message, t);
        writeToFile(logEntry);
    }

    /**
     * Enable/disable logging to a gzipped file.
     *
     * @param enable  True to enable file logging, false to disable.
     * @param logFile The file to write logs to (will be gzipped).
     */
    public static void setLogToFile(boolean enable, File logFile) {
        close(); // Close existing streams
        logToFile = enable;
        if (enable && logFile != null) {
            try {
                fileOutputStream = new FileOutputStream(logFile);
                gzipOutputStream = new GzipCompressorOutputStream(fileOutputStream);
                fileWriter = new BufferedWriter(new OutputStreamWriter(gzipOutputStream));
            } catch (IOException e) {
                Log.e(TAG, "Failed to open log file: " + e.getMessage());
                close();
            }
        }
    }

    /**
     * Write log entry to file.
     */
    private static void writeToFile(String logEntry) {
        if (logToFile && fileWriter != null) {
            try {
                fileWriter.write(logEntry);
                fileWriter.newLine();
                fileWriter.flush();
            } catch (IOException e) {
                Log.e(TAG, "Failed to write log to file: " + e.getMessage());
            }
        }
    }

    /**
     * Close the log file and associated streams.
     */
    public static void close() {
        if (fileWriter != null) {
            try {
                fileWriter.close();
            } catch (IOException e) {
                Log.e(TAG, "Failed to close log writer: " + e.getMessage());
            }
            fileWriter = null;
        }
        if (gzipOutputStream != null) {
            try {
                gzipOutputStream.close();
            } catch (IOException e) {
                Log.e(TAG, "Failed to close gzip stream: " + e.getMessage());
            }
            gzipOutputStream = null;
        }
        if (fileOutputStream != null) {
            try {
                fileOutputStream.close();
            } catch (IOException e) {
                Log.e(TAG, "Failed to close log file stream: " + e.getMessage());
            }
            fileOutputStream = null;
        }
        logToFile = false;
    }
}
