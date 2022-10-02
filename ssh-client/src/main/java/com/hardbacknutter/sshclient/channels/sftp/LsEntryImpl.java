package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ChannelSftp;

import java.util.Objects;


class LsEntryImpl
        implements ChannelSftp.LsEntry {

    @NonNull
    private final String filename;
    @Nullable
    private String longname;
    @NonNull
    private final SftpATTRS attrs;

    LsEntryImpl(@NonNull final String filename,
                @Nullable final String longname,
                @NonNull final SftpATTRS attrs) {
        this.filename = filename;
        this.longname = longname;
        this.attrs = attrs;
    }

    @Override
    @NonNull
    public String getFilename() {
        return filename;
    }

    @Override
    @NonNull
    public String getLongname() {
        if (longname == null) {
            // generate it from the attrs
            longname = attrs.getAsString() + " " + filename;
        }
        return longname;
    }

    @Override
    @NonNull
    public SftpATTRS getAttrs() {
        return attrs;
    }


    @Override
    public int compareTo(@Nullable final ChannelSftp.LsEntry o)
            throws NullPointerException, ClassCastException {
        Objects.requireNonNull(o);
        return filename.compareTo(o.getFilename());
    }

    @Override
    public boolean equals(@Nullable final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final ChannelSftp.LsEntry that = (ChannelSftp.LsEntry) o;
        // longname is ignored
        return filename.equals(that.getFilename())
                && attrs.equals(that.getAttrs());
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, longname, attrs);
    }

    @Override
    @NonNull
    public String toString() {
        return "LsEntryImpl{"
                + "filename='" + filename + '\''
                + ", longname='" + longname + '\''
                + ", attrs=" + attrs
                + '}';
    }
}
