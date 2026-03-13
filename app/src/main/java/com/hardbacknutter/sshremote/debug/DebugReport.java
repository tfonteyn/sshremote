package com.hardbacknutter.sshremote.debug;

import android.content.Context;
import android.net.Uri;
import android.os.Build;

import androidx.annotation.NonNull;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@SuppressWarnings({"BlockingMethodInNonBlockingContext", "NestedAssignment"})
public class DebugReport {

    private static final int BUFFER_SIZE = 65535;
    private final Collection<File> files = new ArrayList<>();
    @NonNull
    private final Context context;
    @NonNull
    private final String logDirName;
    private final String dateTime;

    /**
     * Constructor.
     *
     * @param context    Current context
     * @param logDirName to collect files from
     */
    public DebugReport(@NonNull final Context context,
                       @NonNull final String logDirName) {
        this.context = context;
        this.logDirName = logDirName;
        // User local zone - it's for THEIR reference.
        dateTime = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    private static void copy(@NonNull final InputStream is,
                             @NonNull final OutputStream os)
            throws IOException {

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            android.os.FileUtils.copy(is, os);

        } else {
            final byte[] buffer = new byte[BUFFER_SIZE];
            int nRead;
            while ((nRead = is.read(buffer)) > 0) {
                os.write(buffer, 0, nRead);
            }
            os.flush();
        }
    }

    public void sendToFile(@NonNull final Uri destUri)
            throws IOException {

        final File logDir = new File(context.getFilesDir(), logDirName);
        files.addAll(collectFiles(logDir));

        final File file = zipAllInfo();
        try (InputStream is = new FileInputStream(file);
             OutputStream os = context.getContentResolver().openOutputStream(destUri)) {
            if (os != null) {
                copy(is, os);
            }
        }
    }

    @NonNull
    private File zipAllInfo()
            throws IOException {

        final File zipFile = new File(context.getCacheDir(),
                                      "SshRemoteBugReport-" + dateTime + ".zip");
        zipFile.deleteOnExit();
        try (ZipOutputStream zipOutputStream = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(zipFile), BUFFER_SIZE))) {

            for (final File file : files) {
                final ZipEntry entry = new ZipEntry(file.getName());
                entry.setTime(file.lastModified());
                entry.setMethod(ZipEntry.DEFLATED);
                zipOutputStream.putNextEntry(entry);
                try (InputStream is = new FileInputStream(file)) {
                    copy(is, zipOutputStream);
                } finally {
                    zipOutputStream.closeEntry();
                }
            }
        }

        return zipFile;
    }

    @NonNull
    private List<File> collectFiles(@NonNull final File dir) {
        final List<File> list = new ArrayList<>();
        // sanity check
        if (dir.isDirectory()) {
            final File[] fileList = dir.listFiles((FileFilter) null);
            if (fileList != null && fileList.length > 0) {
                int i = 0;
                while (i < fileList.length && list.size() < Integer.MAX_VALUE) {
                    if (fileList[i].isFile()) {
                        list.add(fileList[i]);
                    }
                    i++;
                }
            }
        }
        // Sort in reverse order. Newest file first.
        list.sort((o1, o2) -> Long.compare(o2.lastModified(), o1.lastModified()));
        return list.subList(0, Math.min(10, list.size()));
    }
}
