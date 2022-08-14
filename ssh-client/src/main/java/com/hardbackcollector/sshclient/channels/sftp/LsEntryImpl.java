package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Objects;


class LsEntryImpl
        implements LsEntry {

    @NonNull
    private final String filename;
    @NonNull
    private final String longname;
    @NonNull
    private final SftpATTRS attrs;

    LsEntryImpl(@NonNull final String filename,
                @NonNull final String longname,
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
        return longname;
    }

    @Override
    @NonNull
    public SftpATTRS getAttrs() {
        return attrs;
    }


    @Override
    public int compareTo(@Nullable final LsEntry o)
            throws NullPointerException, ClassCastException {
        Objects.requireNonNull(o);
        return filename.compareTo(o.getFilename());
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final LsEntry that = (LsEntry) o;
        return filename.equals(that.getFilename())
                && longname.equals(that.getLongname())
                && attrs.equals(that.getAttrs());
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, longname, attrs);
    }

    @Override
    public String toString() {
        return "LsEntryImpl{"
                + "filename='" + filename + '\''
                + ", longname='" + longname + '\''
                + ", attrs=" + attrs
                + '}';
    }
}
