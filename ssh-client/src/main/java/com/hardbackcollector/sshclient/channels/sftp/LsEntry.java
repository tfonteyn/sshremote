package com.hardbackcollector.sshclient.channels.sftp;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.ChannelSftp;

/**
 * Represents a directory entry, i.e. representing a remote file or directory.
 * <p>
 * A list of objects of this class is returned by {@link ChannelSftp#ls(String)}.
 */
public interface LsEntry extends Comparable<LsEntry> {

    /**
     * Get the file name of this entry.
     */
    @NonNull
    String getFilename();

    /**
     * Get the "longname" of this entry.
     */
    @NonNull
    String getLongname();

    /**
     * Get the attributes of this entry.
     */
    @NonNull
    public SftpATTRS getAttrs();

    /**
     * Objects implementing this interface can be passed as an argument to the
     * {@link ChannelSftp#ls(String, Selector)} method.
     */
    interface Selector {

        int CONTINUE = 0;
        int BREAK = 1;

        /**
         * <p> This method will be invoked by {@link ChannelSftp#ls(String, Selector)}
         * for each file entry. If this method returns {@link #BREAK}
         * the {@code ls} operation will be canceled.
         *
         * @param entry current item from {@code ls}
         *
         * @return {@link #BREAK} or {@link #CONTINUE},
         */
        int select(@NonNull LsEntry entry);
    }
}
