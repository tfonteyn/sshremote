package com.hardbacknutter.sshremote.ssh;

import android.util.Log;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import com.hardbacknutter.sshclient.Logger;

/**
 * URGENT: This is a quick copy/paste/hack... redo this!
 */
@SuppressWarnings({"WeakerAccess", "Unused"})
public class FileLogger
        implements Logger {

    private static final String TAG = "FileLogger";
    /** Keep the last 3 log files. */
    private static final int DEFAULT_LOGFILE_COPIES = 3;

    /** Prefix for logfile entries. Not used on the console. */
    private static final String ERROR = "ERROR";
    private static final String WARN = "WARN";
    private static final String DEBUG = "DEBUG";
    private static final String ERROR_SOURCE_MISSING = "Source does not exist: ";
    private static final String ERROR_FAILED_TO_RENAME = "Failed to rename: ";
    @NonNull
    private final File logDir;
    @NonNull
    private final File backupDir;
    @NonNull
    private final String logFilename;
    @IntRange(from = Logger.NONE, to = Logger.DEBUG)
    private final int level;
    private int copies = DEFAULT_LOGFILE_COPIES;

    /**
     * Constructor.
     *
     * @param logDir   the directory where logs will be written
     * @param filename the base name for the logfile
     */
    public FileLogger(@IntRange(from = Logger.NONE, to = Logger.DEBUG) final int logLevel,
                      @NonNull final File logDir,
                      @NonNull final String filename) {
        this(logLevel, logDir, filename, logDir);
    }

    /**
     * Constructor.
     *
     * @param logDir    the directory where logs will be written
     * @param filename  the base name for the logfile
     * @param backupDir Where to put the backup files.
     *                  Must be on the same volume as the file(s).
     */
    public FileLogger(@IntRange(from = Logger.NONE, to = Logger.DEBUG) final int logLevel,
                      @NonNull final File logDir,
                      @NonNull final String filename,
                      @NonNull final File backupDir) {
        this.logDir = logDir;
        this.logFilename = filename;
        this.backupDir = backupDir;
        this.level = logLevel;
    }

    @Override
    public boolean isEnabled(final int level) {
        return level >= this.level;
    }

    @Override
    public void log(final int level,
                    @org.jspecify.annotations.NonNull final String message) {
        writeToLog("SSH" + level, DEBUG, message);
    }

    public void cycleLogs() {
        //noinspection CheckStyle,OverlyBroadCatchBlock
        try {
            final File logFile = new File(logDir, logFilename);
            if (logFile.exists()) {
                if (logFile.length() > 0) {
                    final File backup = new File(logFile.getPath() + ".bak");
                    // Move/rename the previous/original file
                    makeBackup(backup);
                    // and write the new copy.
                    try (FileInputStream fis = new FileInputStream(logFile);
                         FileOutputStream fos = new FileOutputStream(backup);
                         FileChannel inChannel = fis.getChannel();
                         FileChannel outChannel = fos.getChannel()) {
                        inChannel.transferTo(0, inChannel.size(), outChannel);
                    }
                }
                //noinspection ResultOfMethodCallIgnored
                logFile.delete();
            }
        } catch (@NonNull final Exception ignore) {
            // do nothing - we can't log an error in the logger
        }
    }

    /**
     * Rename the given "file" to "file.1", keeping {@code copies} of the old file,
     * i.e. the number of the copy is added as a SUFFIX to the name.
     * <p>
     * Upon success, the "file" is no longer available.
     * Any exception is ignored. The presence of "file" is not defined, and should be assumed
     * to be no longer available.
     * <p>
     * <strong>Important:</strong> it's a 'rename', so single volume use only!
     *
     * @param file file to rename
     */
    private void makeBackup(@NonNull final File file) {

        final String backupFilePath = new File(backupDir, file.getName()).getPath();

        // remove the oldest copy (if there is one)
        File previous = new File(backupFilePath + "." + copies);
        //noinspection OverlyBroadCatchBlock
        try {
            if (previous.exists()) {
                //noinspection ResultOfMethodCallIgnored
                previous.delete();
            }

            // now bump each copy up one suffix.
            for (int i = copies - 1; i > 0; i--) {
                final File current = new File(backupFilePath + "." + i);
                if (current.exists()) {
                    rename(current, previous);
                }
                previous = current;
            }

            // Rename the current file giving it a suffix.
            if (file.exists()) {
                rename(file, previous);
            }
        } catch (@NonNull final Exception e) {
            Log.e(TAG, "Failed to makeBackup", e);
        }
    }

    /**
     * ENHANCE: make suitable for multiple filesystems.
     * Android docs {@link File#renameTo(File)}: Both paths be on the same mount point.
     *
     * @param source      File to rename
     * @param destination new name
     *
     * @throws FileNotFoundException if the source does not exist
     * @throws IOException           on generic/other IO failures
     */
    private void rename(@NonNull final File source,
                        @NonNull final File destination)
            throws IOException {

        //sanity check
        if (source.getAbsolutePath().equals(destination.getAbsolutePath())) {
            return;
        }

        if (!source.exists()) {
            throw new FileNotFoundException(ERROR_SOURCE_MISSING + source);
        }

        try {
            if (source.renameTo(destination)) {
                return;
            }
            throw new IOException(ERROR_FAILED_TO_RENAME + source + " TO " + destination);

        } catch (@NonNull final SecurityException e) {
            // SecurityException is never thrown as the
            // System.getSecurityManager() always return null
            throw new IOException(ERROR_FAILED_TO_RENAME + source + " TO " + destination, e);
        }
    }

    /**
     * This is an expensive call... file open+close... BOOOO!
     * <p>
     * ENHANCE: implement a FIFO queue for the log messages.
     *
     * @param tag     log tag
     * @param type    warn,error,...
     * @param message to write
     */
    private synchronized void writeToLog(@NonNull final String tag,
                                         @NonNull final String type,
                                         @NonNull final String message) {
        // UTC based
        final String fullMsg = LocalDateTime.now(ZoneOffset.UTC)
                                            .format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                               + '|' + tag + '|' + type + '|' + message;

        //noinspection OverlyBroadCatchBlock,CheckStyle
        try {
            final File logFile = new File(logDir, logFilename);
            try (FileOutputStream fos = new FileOutputStream(logFile, true);
                 OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
                 PrintWriter out = new PrintWriter(new BufferedWriter(osw))) {
                out.println(fullMsg);
            }
        } catch (@NonNull final Exception ignore) {
            // do nothing - we can't log an error in the logger
        }
    }
}
