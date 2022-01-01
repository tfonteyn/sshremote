package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ChannelSftp;

import java.util.Objects;

/**
 * Represents a directory entry, representing a remote file or directory.
 * <p>
 * A list of objects of this class is returned by
 * {@link ChannelSftp#ls}.
 */
public class LsEntry
        implements Comparable<LsEntry> {

    @NonNull
    private String filename;
    @NonNull
    private String longname;
    @NonNull
    private SftpATTRS attrs;

    LsEntry(@NonNull final String filename,
            @NonNull final String longname,
            @NonNull final SftpATTRS attrs) {
        this.filename = filename;
        this.longname = longname;
        this.attrs = attrs;
    }

    /**
     * gets the file name of this file.
     */
    @NonNull
    public String getFilename() {
        return filename;
    }

    void setFilename(@NonNull final String filename) {
        this.filename = filename;
    }

    /**
     * returns the "longname" of a file.
     */
    @NonNull
    public String getLongname() {
        return longname;
    }

    void setLongname(@NonNull final String longname) {
        this.longname = longname;
    }

    /**
     * return the attributes of the file.
     */
    @NonNull
    public SftpATTRS getAttrs() {
        return attrs;
    }

    void setAttrs(@NonNull final SftpATTRS attrs) {
        this.attrs = attrs;
    }

    @Override
    public int compareTo(@Nullable final LsEntry o)
            throws ClassCastException {
        if (o != null) {
            return filename.compareTo(o.getFilename());
        }
        throw new ClassCastException("a descendant of LsEntry must be given.");
    }

    @Override
    public boolean equals(@Nullable final Object o) {
        if (!(o instanceof LsEntry)) {
            return false;
        }
        return compareTo((LsEntry) o) == 0;
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, longname, attrs);
    }

    /**
     * Objects implementing this interface can be passed as an argument for
     * {@link ChannelSftp#ls} method.
     */
    public interface Selector {

        int CONTINUE = 0;
        int BREAK = 1;

        /**
         * <p> The {@code select} method will be invoked in {@code ls}
         * method for each file entry. If this method returns {@link #BREAK}
         * {@code ls} will be canceled.
         *
         * @param entry current item from {@code ls}
         *
         * @return {@link #BREAK} or {@link #CONTINUE},
         */
        int select(@NonNull LsEntry entry);
    }
}
