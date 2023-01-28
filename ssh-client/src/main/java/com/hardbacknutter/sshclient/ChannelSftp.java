package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.channels.sftp.SftpATTRS;
import com.hardbacknutter.sshclient.channels.sftp.SftpException;
import com.hardbacknutter.sshclient.channels.sftp.SftpStatVFS;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;

@SuppressWarnings("unused")
public interface ChannelSftp
        extends ChannelSession {

    String NAME = "sftp";

    /**
     * Set the remote filename encoding.
     * This should be the the same encoding actually used on the server.
     * <p>
     * The default is UTF-8.
     *
     * @param encoding which is used on the server
     *
     * @throws UnsupportedEncodingException if this client does not support the
     *                                      desired server encoding
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.2">
     * SFTP v3 has no specific rule on filename encoding</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-04#section-6.2">
     * SFTP v4 enforces all file names to be UTF-8</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-05#section-6.2">
     * SFTP v5 enforces all file names to be UTF-8</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13#section-6">
     * SFTP v6 extensions to deal with encoding</a>
     */
    void setFilenameEncoding(@NonNull String encoding)
            throws UnsupportedEncodingException;

    /**
     * returns the server's protocol version number.
     */
    int getServerVersion()
            throws SftpException;

    /**
     * sftp command "version"
     *
     * @return the protocol version number supported by this client.
     */
    @NonNull
    String version();

    /**
     * local command "lcd"
     * <p>
     * Changes the <em>current local directory<em>.
     *
     * @param path a directory path, absolute or relative to the current local path.
     *
     * @throws SftpException if the mentioned path is not a directory.
     * @see #lpwd
     */
    void lcd(@NonNull String path)
            throws SftpException;

    /**
     * local command "lpwd"
     *
     * @return the <em>current local directory</em> in absolute form.
     *
     * @see #lcd
     */
    @Nullable
    String lpwd();

    /**
     * sftp command "cd"
     * <p>
     * Changes the <em>current remote directory</em>.
     * <p>
     * This checks the existence and accessibility of the indicated directory,
     * and changes the <em>current remote directory</em> setting.
     *
     * @param path a directory path, absolute or relative to the <em>current remote directory</em>.
     *
     * @throws SftpException if the named path does not indicate a directory,
     *                       if it is not accessible by the user, or some other problem occurs.
     * @see #pwd
     */
    void cd(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "pwd"
     *
     * @return the <em>current remote directory</em> in absolute form.
     *
     * @see #cd
     */
    @NonNull
    String pwd()
            throws SftpException;

    /**
     * returns the absolute path of the remote home directory.
     */
    @NonNull
    String getHome()
            throws SftpException;

    /**
     * sftp command "mkdir"
     * <p>
     * creates a new remote directory.
     *
     * @param path the path of the new directory, relative
     *             to the <em>current remote directory</em>.
     */
    void mkdir(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "rmdir"
     * <p>
     * Removes one or several remote directories.
     *
     * @param path a glob pattern of the directories to be removed, relative
     *             to the <em>current remote directory</em>.
     */
    void rmdir(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "rm"
     * <p>
     * removes one or several files.
     *
     * @param path a glob pattern of the files to be removed, relative to the
     *             <em>current remote directory</em>.
     */
    void rm(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "rename"
     * <p>
     * Renames a file or directory.
     *
     * @param oldPath the old name of the file, relative to the
     *                <em>current remote directory</em>.
     * @param newPath the new name of the file, relative to the
     *                <em>current remote directory</em>.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.5">
     * Internet draft, 6.5 Removing and Renaming Files</a>
     */
    void rename(@NonNull String oldPath,
                @NonNull String newPath)
            throws SftpException;

    /**
     * sftp command "ls"
     * <p>
     * List the contents of a remote directory.
     *
     * @param path a path relative to the <em>current remote directory</em>.
     *             The pattern can contain glob pattern wildcards ({@code *} or {@code ?})
     *             in the last component (i.e. after the last file-separator char).
     *
     * @return a list of {@link LsEntry} objects.
     */
    @NonNull
    List<LsEntry> ls(@NonNull String path)
            throws SftpException;

    /**
     * List files specified by the remote {@code path}.
     * <p>
     * Each file/directory will be passed to the {@link LsEntry.Selector#select(LsEntry)} method.
     * This functions similar to the {@link java.io.FileFilter} interface.
     * <p>
     * If {@code select} returns {@code Selector#BREAK}, the ls-operation will be
     * canceled immediately.
     * <p>
     * A simple 'get all' selector:
     * <pre>
     *     final List<LsEntry> entries = new ArrayList<>();
     *     final Selector selector = entry -> {
     *             entries.add(entry);
     *             return Selector.CONTINUE;
     *     };
     *     ls(path, selector);
     *     // entries will now contain the full list
     * </pre>
     *
     * @param path     a path relative to the
     *                 <em>current remote directory</em>.
     *                 The path can contain glob pattern wildcards ({@code *} or {@code ?})
     *                 in the last component (i.e. after the last {@code /}).
     * @param selector see above
     *
     * @see LsEntry.Selector
     */
    void ls(@NonNull String path,
            @NonNull LsEntry.Selector selector)
            throws SftpException;

    /**
     * sftp command "ln" , "ln -s" and "symlink"
     * <p>
     * Creates a new hard link; or pass {@code true} to create a soft link instead.
     *
     * <p>
     * <strong>Note:</strong> The protocol draft declares the two parameters
     * in the reverse order (i.e. first linkpath, then targetpath), but because
     * of an erroneous implementation in (both sides of) OpenSSH, the
     * de facto protocol is now what is implemented here (first targetpath,
     * then linkpath).
     * If you are speaking to a SFTP server which implements the protocol
     * as specified, you might have to swap the arguments.
     * </p>
     *
     * @param targetPath the path of the link target,  relative to the
     *                   <em>current remote directory</em>
     * @param linkPath   the path of the link to be created, relative to the
     *                   <em>current remote directory</em>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.10">
     * Internet draft, 6.10.  Dealing with Symbolic links</a>
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     * OpenSSH protocol deviations.</a>
     */
    void ln(@NonNull String targetPath,
            @NonNull String linkPath,
            boolean softLink)
            throws SftpException;

    /**
     * reads a symbolic link.
     *
     * @param path a path relative to the
     *             <em>current remote directory</em>,
     *             which should correspond to a symbolic link.
     *
     * @return the link target, relative to the location
     * of the link itself (this could be depending on the server).
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.10">
     * Internet draft, 6.10.  Dealing with Symbolic links</a>
     */
    @NonNull
    String readlink(@NonNull String path)
            throws SftpException;

    /**
     * converts a remote path to its absolute (and to a certain degree canonical) version.
     *
     * @param path a path name, relative to the
     *             <em>current remote directory</em>.
     *
     * @return an absolute version of the path (but not resolving symbolic links).
     */
    @NonNull
    String realpath(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "chgrp"
     * <p>
     * Changes the owner group of one or several remote files.
     *
     * @param gid  the identifier of the new group.
     * @param path a glob pattern of the files to be changed, relative to the
     *             <em>current remote directory</em>.
     */
    void chgrp(int gid,
               @NonNull String path)
            throws SftpException;

    /**
     * sftp command "chown"
     * <p>
     * Changes the owning user of one or several remote files.
     *
     * @param uid  the identifier of the new owner.
     * @param path a glob pattern of the files to be changed, relative to the
     *             <em>current remote directory</em>.
     */
    void chown(int uid,
               @NonNull String path)
            throws SftpException;

    /**
     * sftp command "chmod"
     * <p>
     * Changes the permissions of one or several remote files.
     *
     * @param permissions the new permission pattern.
     *                    This may be modified by a current mask before being applied.
     * @param path        a glob pattern of the files to be changed, relative to the
     *                    <em>current remote directory</em>.
     */
    void chmod(int permissions,
               @NonNull String path)
            throws SftpException;

    /**
     * Retrieves the file attributes of a file or directory.
     * <p>
     * This method <strong>follows symbolic links</strong> (i.e. returns
     * the attributes of the target and not the link).
     *
     * @param path the path of the file or directory, relative
     *             to the <em>current remote directory</em>.
     *
     * @return an SftpAttrs object containing the file's attributes.
     *
     * @see #lstat(String)
     */
    @NonNull
    SftpATTRS stat(@NonNull String path)
            throws SftpException;

    /**
     * Retrieves the file attributes of a file or directory.
     * <p>
     * This method <strong>does not follows symbolic links</strong> (i.e. returns
     * the attributes of the link and not the target).
     *
     * @param path the path of the file or directory, relative
     *             to the <em>current remote directory</em>.
     *
     * @return an SftpAttrs object containing the file's attributes.
     *
     * @see #stat(String)
     */
    @NonNull
    SftpATTRS lstat(@NonNull String path)
            throws SftpException;

    /**
     * "statvfs@openssh.com" correspond to the statvfs and POSIX system interfaces.
     *
     * @param path the path of the file or directory, relative
     *             to the <em>current remote directory</em>.
     *
     * @return an SftpStatVFS object containing the file's attributes.
     *
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     * PROTOCOL</a>
     */
    @NonNull
    SftpStatVFS statVFS(@NonNull String path)
            throws SftpException;

    /**
     * Changes attributes of a remote file or directory.
     *
     * @param path the path of the file or directory, relative
     *             to the <em>current remote directory</em>.
     * @param attr the attribute set containing the attributes to be changed.
     */
    void setStat(@NonNull String path,
                 @NonNull SftpATTRS attr)
            throws SftpException;

    /**
     * Changes the modification time of one or more remote files.
     * <p>
     * This is the equivalent of "touch -m".
     *
     * @param modificationTime the new modification time, in seconds from the unix epoch.
     * @param path             a glob pattern of the files to be changed, relative to the
     *                         <em>current remote directory</em>.
     */
    void setModificationTime(int modificationTime,
                             @NonNull String path)
            throws SftpException;

    /**
     * Starts downloading a file as an InputStream.
     *
     * @param srcFilename the source file name, relative to the
     *                    <em>current remote directory</em>.
     *
     * @return an InputStream from which the contents of the file can be read.
     *
     * @see #get(String, ProgressListener, long)
     */
    @NonNull
    default InputStream get(@NonNull final String srcFilename)
            throws SftpException {
        return get(srcFilename, null, 0L);
    }

    /**
     * Starts downloading a file as an InputStream.
     *
     * @param srcFilename      the source file name, relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     *
     * @return an InputStream from which the contents of the file can be read.
     *
     * @see #get(String, ProgressListener, long)
     */
    @NonNull
    default InputStream get(@NonNull final String srcFilename,
                            @Nullable final ProgressListener progressListener)
            throws SftpException {
        return get(srcFilename, progressListener, 0L);
    }

    /**
     * Starts downloading a file as an InputStream.
     *
     * @param srcPath          the source file name, relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     * @param initialOffset    the position in the remote file where
     *                         we should start the download
     *
     * @return an InputStream from which the contents of the file can be read.
     */
    @NonNull
    InputStream get(@NonNull String srcPath,
                    @Nullable ProgressListener progressListener,
                    long initialOffset)
            throws SftpException;

    /**
     * Downloads a file to an OutputStream; starts from start of the file.
     *
     * @see #get(String, OutputStream, ProgressListener, Mode, long)
     */
    default void get(@NonNull final String src,
                     @NonNull final OutputStream outputStream)
            throws SftpException {
        get(src, outputStream, null, Mode.Overwrite, 0);
    }

    /**
     * Downloads a file to an OutputStream; starts from start of the file.
     *
     * @see #get(String, OutputStream, ProgressListener, Mode, long)
     */
    default void get(@NonNull final String src,
                     @NonNull final OutputStream outputStream,
                     @Nullable final ProgressListener progressListener)
            throws SftpException {
        get(src, outputStream, progressListener, Mode.Overwrite, 0);
    }

    /**
     * Downloads a file to a specified filename or directory using
     * {@link Mode#Overwrite}.
     *
     * @see #get(String, String, ProgressListener, Mode)
     */
    default void get(@NonNull final String src,
                     @NonNull final String dst)
            throws SftpException {
        get(src, dst, null, Mode.Overwrite);
    }

    /**
     * Downloads a file to a specified filename or directory using
     * {@link Mode#Overwrite}.
     *
     * @see #get(String, String, ProgressListener, Mode)
     */
    default void get(@NonNull final String src,
                     @NonNull final String dst,
                     @Nullable final ProgressListener progressListener)
            throws SftpException {
        get(src, dst, progressListener, Mode.Overwrite);
    }

    /**
     * Downloads a file to a specified filename or directory.
     *
     * @param srcPath the source file name, relative to the
     *                <em>current remote directory</em>.
     * @param dstPath the destination file name or directory, relative to the
     *                <em>current local directory</em>.
     * @param monitor (optional) progress listener
     * @param mode    the transfer {@link Mode}
     *
     * @throws SftpException if some problem occurred.
     */
    void get(@NonNull String srcPath,
             @NonNull String dstPath,
             @Nullable ProgressListener monitor,
             @NonNull Mode mode)
            throws SftpException;

    /**
     * Downloads a file to an OutputStream.
     *
     * @param srcPath   the source file name, relative to the
     *                  <em>current remote directory</em>.
     * @param dstStream the destination output stream.
     * @param monitor   (optional) progress listener
     * @param mode      the transfer {@link Mode}
     * @param skip      only used If the {@link Mode} == {@link Mode#Resume} :
     *                  the position in the remote file where we should start the download
     *
     * @throws SftpException if some problem occurred.
     */
    void get(@NonNull String srcPath,
             @NonNull OutputStream dstStream,
             @Nullable ProgressListener monitor,
             @NonNull Mode mode,
             long skip)
            throws SftpException;

    /**
     * Uploads a file from an InputStream using {@link Mode#Overwrite}.
     *
     * @param src the source file, in the form of an InputStream
     * @param dst the remote destination file name, relative to the
     *            <em>current remote directory</em>.
     *
     * @see #put(InputStream, String, ProgressListener, Mode)
     */
    default void put(@NonNull final InputStream src,
                     @NonNull final String dst)
            throws SftpException {
        put(src, dst, null, Mode.Overwrite);
    }

    /**
     * Uploads a file from an InputStream.
     *
     * @param src  the source file, in the form of an InputStream
     * @param dst  the remote destination file name, relative to the
     *             <em>current remote directory</em>.
     * @param mode the transfer {@link Mode}
     *
     * @see #put(InputStream, String, ProgressListener, Mode)
     */
    default void put(@NonNull final InputStream src,
                     @NonNull final String dst,
                     @NonNull final Mode mode)
            throws SftpException {
        put(src, dst, null, mode);
    }

    /**
     * Uploads a file from an InputStream using {@link Mode#Overwrite}.
     *
     * @param src              the source file, in form of an input stream.
     * @param dst              the remote destination file name, relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     *
     * @see #put(InputStream, String, ProgressListener, Mode)
     */
    default void put(@NonNull final InputStream src,
                     @NonNull final String dst,
                     @Nullable final ProgressListener progressListener)
            throws SftpException {
        put(src, dst, progressListener, Mode.Overwrite);
    }

    /**
     * Starts an upload from an OutputStream using {@link Mode#Overwrite}.
     *
     * @param dst the remote destination file name, relative to the
     *            <em>current remote directory</em>.
     *
     * @return an OutputStream to which the application should write the file contents.
     *
     * @see #put(String, ProgressListener, Mode, long)
     */
    @NonNull
    default OutputStream put(@NonNull final String dst)
            throws SftpException {
        return put(dst, null, Mode.Overwrite, 0);
    }

    /**
     * Starts an upload from an OutputStream.
     *
     * @param dst  the remote destination file name, relative to the
     *             <em>current remote directory</em>.
     * @param mode the transfer {@link Mode}
     *
     * @return an OutputStream to which the application should write the file contents.
     *
     * @see #put(String, ProgressListener, Mode, long)
     */
    @NonNull
    default OutputStream put(@NonNull final String dst,
                             @NonNull final Mode mode)
            throws SftpException {
        return put(dst, null, mode, 0);
    }

    /**
     * Starts an upload from an OutputStream.
     *
     * @param dst              the remote destination file name, relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     * @param mode             the transfer {@link Mode}
     *
     * @return an OutputStream to which the application should write the file contents.
     *
     * @see #put(String, ProgressListener, Mode, long)
     */
    @NonNull
    default OutputStream put(@NonNull final String dst,
                             @Nullable final ProgressListener progressListener,
                             @NonNull final Mode mode)
            throws SftpException {
        return put(dst, progressListener, mode, 0);
    }

    /**
     * Uploads a file using {@link Mode#Overwrite}.
     *
     * @param src the local source file name, absolute or relative to the
     *            <em>current local directory</em>.
     * @param dst the remote destination file name, absolute or relative to the
     *            <em>current remote directory</em>.
     *
     * @see #put(String, String, ProgressListener, Mode)
     */
    default void put(@NonNull final String src,
                     @NonNull final String dst)
            throws SftpException {
        put(src, dst, null, Mode.Overwrite);
    }

    /**
     * Uploads a file.
     *
     * @param src  the local source file name, absolute or relative to the
     *             <em>current local directory</em>.
     * @param dst  the remote destination file name, absolute or relative to the
     *             <em>current remote directory</em>.
     * @param mode the transfer {@link Mode}
     *
     * @see #put(String, String, ProgressListener, Mode)
     */
    default void put(@NonNull final String src,
                     @NonNull final String dst,
                     @NonNull final Mode mode)
            throws SftpException {
        put(src, dst, null, mode);
    }

    /**
     * Uploads a file using {@link Mode#Overwrite}.
     *
     * @param src              the local source file name, absolute or relative to the
     *                         <em>current local directory</em>.
     * @param dst              the remote destination file name, absolute or relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     *
     * @see #put(String, String, ProgressListener, Mode)
     */
    default void put(@NonNull final String src,
                     @NonNull final String dst,
                     @Nullable final ProgressListener progressListener)
            throws SftpException {
        put(src, dst, progressListener, Mode.Overwrite);
    }

    /**
     * Starts an upload by OutputStream.
     * <p>
     * The returned output stream should be used by the application to
     * write data, which will then be uploaded to the remote file.
     * Closing the stream will finish the upload.
     *
     * @param dstPath          the remote destination file name, relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     * @param mode             the transfer {@link Mode}
     * @param offset           the position in the remote file where we want to start writing.
     *                         In the {@link Mode#Resume} and {@link Mode#Append}
     *                         modes, this is added to the current size of the file
     *                         (i.e. an offset > 0 creates a sparse section of that
     *                         size in the file).
     *
     * @return an OutputStream to which the application should write the file contents.
     */
    @NonNull
    OutputStream put(@NonNull String dstPath,
                     @Nullable ProgressListener progressListener,
                     @NonNull Mode mode,
                     long offset)
            throws SftpException;

    /**
     * Uploads a file.
     * <p>
     * If the destination is a filename, the source must also be a single file.
     * <p>
     * If the destination is a directory, the source can contain wildcards.
     * The transfer mode will be applied to ALL resolved filenames.
     *
     * @param srcFilename      the local source file name, absolute or relative to the
     *                         <em>current local directory</em>.
     * @param dstPath          the remote destination file name, absolute or relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     * @param mode             the transfer {@link Mode}
     */
    void put(@NonNull String srcFilename,
             @NonNull String dstPath,
             @Nullable ProgressListener progressListener,
             @NonNull Mode mode)
            throws SftpException;

    /**
     * Uploads a file from an input stream.
     *
     * @param srcStream        the source file, in the form of an input stream.
     * @param dstPath          the remote destination file name, relative to the
     *                         <em>current remote directory</em>.
     * @param progressListener (optional) progress listener
     * @param mode             the transfer {@link Mode}
     */
    void put(@NonNull InputStream srcStream,
             @NonNull String dstPath,
             @Nullable ProgressListener progressListener,
             @NonNull Mode mode)
            throws SftpException;

    /**
     * file transfer mode.
     */
    enum Mode {
        /**
         * overwrite the existing file, if any.
         */
        Overwrite,
        /**
         * append to existing file, if any.
         */
        Append,
        /**
         * Resume an interrupted upload/download.
         * This transfers only the part of the source file which is beyond
         * the existing destination file's length.
         */
        Resume
    }

    /**
     * file transfer direction.
     */
    enum Direction {
        /**
         * Direction constant for upload.
         */
        Put,
        /**
         * Direction constant for download.
         */
        Get
    }

    /**
     * A callback to get information about the progress of a file transfer operation.
     * <p>
     * An application will implement this interface to get information
     * about a running file transfer, and maybe show it to the user.
     * <p>
     * Additionally, this interface enables the application to stop the
     * transfer by returning {@code false} from the {@link #count count} method.
     * <p>
     * Several of the {@link ChannelSftp}'s {@code put} and {@code get} methods
     * take an object of this type, and will call its methods as defined here.
     *
     * @see ChannelSftp
     */
    interface ProgressListener {

        long UNKNOWN_SIZE = -1L;

        /**
         * Will be called when a new operation starts.
         *
         * @param direction flag indicating the direction of transfer
         * @param src       the source file name.
         * @param dest      the destination file name.
         * @param max       the final count (i.e. length of file to transfer).
         */
        void init(@NonNull Direction direction,
                  @NonNull String src,
                  @NonNull String dest,
                  long max);

        /**
         * Will be called periodically as more data is transferred.
         *
         * @param count the number of bytes transferred since the last call to #count
         *              (i.e. the count is NOT incremental)
         *
         * @return {@code true} if the transfer should go on,
         * {@code false} if the transfer should be cancelled.
         */
        boolean count(long count);

        /**
         * Will be called when the transfer ended, either because all the data
         * was transferred, or because the transfer was cancelled.
         */
        void end();

    }

    /**
     * Represents a directory entry, i.e. representing a remote file or directory.
     * <p>
     * A list of objects of this class is returned by {@link ChannelSftp#ls(String)}.
     */
    interface LsEntry extends Comparable<LsEntry> {

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
        SftpATTRS getAttrs();

        /**
         * Objects implementing this interface can be passed as an argument to the
         * {@link ChannelSftp#ls(String, Selector)} method.
         */
        interface Selector {

            /**
             * <p> This method will be invoked by {@link ChannelSftp#ls(String, Selector)}
             * for each file entry. If this method returns {@code false}
             * the {@code ls} operation will be canceled.
             *
             * @param entry current item from {@code ls}
             *
             * @return {@code true} to keep reading, or {@code false} to interrupt.
             */
            boolean select(@NonNull LsEntry entry);
        }
    }
}
