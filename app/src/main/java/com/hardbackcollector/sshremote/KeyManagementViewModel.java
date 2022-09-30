package com.hardbackcollector.sshremote;

import android.content.Context;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.ViewModel;

import com.hardbackcollector.sshclient.hostkey.HostKey;
import com.hardbackcollector.sshremote.ssh.SshHelper;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class KeyManagementViewModel
        extends ViewModel {

    private List<KeyManagementViewModel.HostLine> mList;

    private String fingerPrintAlgorithm;
    private boolean mImportIsAppend;

    public void init(@NonNull final Context context) {
        if (fingerPrintAlgorithm == null) {
            // using hardcoded md5 for now... maybe just use the default which is SSH-256?
            fingerPrintAlgorithm = "MD5";

            try {
                mList = readFile(context.openFileInput(SshHelper.KNOWN_HOSTS));
            } catch (final IOException | NoSuchAlgorithmException ignore) {
                mList = new ArrayList<>();
            }
        }
    }

    @NonNull
    List<HostLine> getHostList() {
        return mList;
    }

    public void save(@NonNull final Context context)
            throws IOException {
        try (final OutputStream os = context.openFileOutput(SshHelper.KNOWN_HOSTS, 0)) {
            writeFile(os);
        }
    }

    void setImportIsAppend(final boolean append) {
        mImportIsAppend = append;
    }

    void startImport(@NonNull final Context context,
                     @NonNull final Uri uri)
            throws IOException, NoSuchAlgorithmException {
        List<HostLine> tmp;
        try (final InputStream is = context.getContentResolver().openInputStream(uri)) {
            tmp = readFile(is);
        }
        if (!mImportIsAppend) {
            mList.clear();
        }
        mList.addAll(tmp);

        tmp = mList.stream().distinct().collect(Collectors.toList());
        mList.clear();
        mList.addAll(tmp);
    }

    void startExport(@NonNull final Context context,
                     @NonNull final Uri uri)
            throws IOException {
        try (final OutputStream os = context.getContentResolver().openOutputStream(uri)) {
            writeFile(os);
        }
    }

    @NonNull
    private List<HostLine> readFile(@NonNull final InputStream is)
            throws IOException, NoSuchAlgorithmException {
        final List<KeyManagementViewModel.HostLine> list = new ArrayList<>();

        //noinspection ImplicitDefaultCharsetUsage
        try (final InputStreamReader isr = new InputStreamReader(is);
             final BufferedReader br = new BufferedReader(isr)) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.startsWith("#") && !line.startsWith(" ")) {
                    final String[] parts = line.split(" ");
                    if (parts.length == 3) {
                        final byte[] key = Base64.getDecoder().decode(parts[2]);
                        final String fp = HostKey.getFingerPrint(fingerPrintAlgorithm, key);
                        list.add(new HostLine(parts[0], parts[1], fp, line));
                    }
                }
            }
        }

        return list;
    }

    private void writeFile(@NonNull final OutputStream os)
            throws IOException {
        //noinspection ImplicitDefaultCharsetUsage
        try (final OutputStreamWriter osr = new OutputStreamWriter(os);
             BufferedWriter bw = new BufferedWriter(osr)) {
            for (final HostLine hostLine : mList) {
                bw.write(hostLine.fullLine);
                bw.write("\n");
            }
        }
    }

    static class HostLine {

        @NonNull
        final String host;
        @NonNull
        final String type;
        @NonNull
        final String fingerprint;
        @NonNull
        private final String fullLine;

        HostLine(@NonNull final String host,
                 @NonNull final String type,
                 @NonNull final String fingerprint,
                 @NonNull final String fullLine) {
            this.host = host;
            this.type = type;
            this.fingerprint = fingerprint;
            this.fullLine = fullLine;
        }

        @Override
        public boolean equals(@Nullable final Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            final HostLine hostLine = (HostLine) o;
            return fullLine.equals(hostLine.fullLine);
        }

        @Override
        public int hashCode() {
            return Objects.hash(fullLine);
        }
    }
}
