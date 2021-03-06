package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.channels.sftp.LsEntry;
import com.hardbackcollector.sshclient.channels.sftp.SftpATTRS;
import com.hardbackcollector.sshclient.channels.sftp.SftpException;
import com.hardbackcollector.sshclient.channels.sftp.SftpStatVFS;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.List;

@SuppressWarnings("unused")
public interface ChannelSftp
        extends ChannelSession {

    String NAME = "sftp";

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
     * Changes the <a href="#current-directory">current local directory</a>.
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
     * @return the <a href="#current-directory">current local directory</a> in absolute form.
     *
     * @see #lcd
     */
    @Nullable
    String lpwd();

    /**
     * sftp command "cd"
     * <p>
     * Changes the current remote directory.
     * <p>
     * This checks the existence and accessibility of the indicated directory,
     * and changes the <a href="#current-directory">current remote directory</a> setting.
     *
     * @param path a directory path, absolute or relative to the current remote path.
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
     * @return the <a href="#current-directory">current remote directory</a> in absolute form.
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
     *             to the <a href="#current-directory">current remote directory</a>.
     */
    void mkdir(@NonNull String path)
            throws IOException, SshChannelException, GeneralSecurityException;

    /**
     * sftp command "rmdir"
     * <p>
     * Removes one or several remote directories.
     *
     * @param path a glob pattern of the directories to be removed, relative
     *             to the <a href="#current-directory">current remote directory</a>.
     */
    void rmdir(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "rm"
     * <p>
     * removes one or several files.
     *
     * @param path a glob pattern of the files to be removed, relative to the
     *             <a href="#current-directory">current remote directory</a>.
     */
    void rm(@NonNull String path)
            throws SftpException;

    /**
     * sftp command "rename"
     * <p>
     * Renames a file or directory.
     *
     * @param oldPath the old name of the file, relative to the
     *                <a href="#current-directory">current remote directory</a>.
     * @param newPath the new name of the file, relative to the
     *                <a href="#current-directory">current remote directory</a>.
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
     * @param pattern a pattern relative to the
     *                <a href="#current-directory">current remote directory</a>.
     *                The pattern can contain glob pattern wildcards ({@code *} or {@code ?})
     *                in the last component (i.e. after the last {@code /}).
     *
     * @return a list of {@link LsEntry} objects.
     */
    @NonNull
    List<LsEntry> ls(@NonNull String pattern)
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
     * @param oldPath the path of the link target,  relative to the
     *                <a href="#current-directory">current remote directory</a>
     * @param newPath the path of the link to be created, relative to the
     *                <a href="#current-directory">current remote directory</a>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.10">
     * Internet draft, 6.10.  Dealing with Symbolic links</a>
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     * OpenSSH protocol deviations.</a>
     */
    void ln(@NonNull String oldPath,
            @NonNull String newPath,
            boolean softLink)
            throws SftpException;

    /**
     * reads a symbolic link.
     *
     * @param path a path relative to the
     *             <a href="#current-directory">current remote directory</a>,
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
     *             <a href="#current-directory">current remote directory</a>.
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
     *             <a href="#current-directory">current remote directory</a>.
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
     *             <a href="#current-directory">current remote directory</a>.
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
     *                    <a href="#current-directory">current remote directory</a>.
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
     *             to the <a href="#current-directory">current remote directory</a>.
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
     *             to the <a href="#current-directory">current remote directory</a>.
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
     *             to the <a href="#current-directory">current remote directory</a>.
     *
     * @return an SftpStatVFS object containing the file's attributes.
     * <p>
     * http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD
     */
    @NonNull
    SftpStatVFS statVFS(@NonNull String path)
            throws SftpException;

    /**
     * Changes attributes of a remote file or directory.
     *
     * @param path the path of the file or directory, relative
     *             to the <a href="#current-directory">current remote directory</a>.
     * @param attr the attribute set containing the attributes to be changed.
     */
    void setStat(@NonNull String path,
                 @NonNull SftpATTRS attr)
            throws SftpException;

    /**
     * Starts downloading a file as an InputStream.
     *
     * @param srcFilename the source file name, relative to the
     *                    <a href="#current-directory">current remote directory</a>.
     *
     * @return an InputStream from which the contents of the file can be read.
     *
     * @see #get(String, SftpProgressMonitor, long)
     */
    @NonNull
    default InputStream get(@NonNull final String srcFilename)
            throws SftpException {
        return get(srcFilename, null, 0L);
    }

    /**
     * Starts downloading a file as an InputStream.
     *
     * @param srcFilename the source file name, relative to the
     *                    <a href="#current-directory">current remote directory</a>.
     * @param monitor     (optional) progress listener
     *
     * @return an InputStream from which the contents of the file can be read.
     *
     * @see #get(String, SftpProgressMonitor, long)
     */
    @NonNull
    default InputStream get(@NonNull final String srcFilename,
                            @Nullable final SftpProgressMonitor monitor)
            throws SftpException {
        return get(srcFilename, monitor, 0L);
    }

    /**
     * Starts downloading a file as an InputStream.
     *
     * @param srcPath       the source file name, relative to the
     *                      <a href="#current-directory">current remote directory</a>.
     * @param monitor       (optional) progress listener
     * @param initialOffset the position in the remote file where
     *                      we should start the download
     *
     * @return an InputStream from which the contents of the file can be read.
     */
    @NonNull
    InputStream get(@NonNull String srcPath,
                    @Nullable SftpProgressMonitor monitor,
                    long initialOffset)
            throws SftpException;

    /**
     * Downloads a file to an OutputStream; starts from start of the file.
     *
     * @see #get(String, OutputStream, SftpProgressMonitor, Mode, long)
     */
    default void get(@NonNull final String src,
                     @NonNull final OutputStream outputStream)
            throws SftpException {
        get(src, outputStream, null, Mode.Overwrite, 0);
    }

    /**
     * Downloads a file to an OutputStream; starts from start of the file.
     *
     * @see #get(String, OutputStream, SftpProgressMonitor, Mode, long)
     */
    default void get(@NonNull final String src,
                     @NonNull final OutputStream outputStream,
                     @Nullable final SftpProgressMonitor monitor)
            throws SftpException {
        get(src, outputStream, monitor, Mode.Overwrite, 0);
    }

    /**
     * Downloads a file to a specified filename or directory using
     * {@link Mode#Overwrite}.
     *
     * @see #get(String, String, SftpProgressMonitor, Mode)
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
     * @see #get(String, String, SftpProgressMonitor, Mode)
     */
    default void get(@NonNull final String src,
                     @NonNull final String dst,
                     @Nullable final SftpProgressMonitor monitor)
            throws SftpException {
        get(src, dst, monitor, Mode.Overwrite);
    }

    /**
     * Downloads a file to a specified filename or directory.
     *
     * @param srcPath the source file name, relative to the
     *                <a href="#current-directory">current remote directory</a>.
     * @param dstPath the destination file name or directory, relative to the
     *                <a href="#current-directory">current local directory</a>.
     * @param monitor (optional) progress listener
     * @param mode    the transfer {@link Mode}
     *
     * @throws SftpException if some problem occurred.
     */
    void get(@NonNull String srcPath,
             @NonNull String dstPath,
             @Nullable SftpProgressMonitor monitor,
             @NonNull Mode mode)
            throws SftpException;

    /**
     * Downloads a file to an OutputStream.
     *
     * @param srcPath   the source file name, relative to the
     *                  <a href="#current-directory">current remote directory</a>.
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
             @Nullable SftpProgressMonitor monitor,
             @NonNull Mode mode,
             long skip)
            throws SftpException;

    /**
     * Uploads a file from an InputStream using {@link Mode#Overwrite}.
     *
     * @param src the source file, in the form of an InputStream
     * @param dst the remote destination file name, relative to the
     *            <a href="#current-directory">current remote directory</a>.
     *
     * @see #put(InputStream, String, SftpProgressMonitor, Mode)
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
     *             <a href="#current-directory">current remote directory</a>.
     * @param mode the transfer {@link Mode}
     *
     * @see #put(InputStream, String, SftpProgressMonitor, Mode)
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
     * @param src     the source file, in form of an input stream.
     * @param dst     the remote destination file name, relative to the
     *                <a href="#current-directory">current remote directory</a>.
     * @param monitor (optional) progress listener
     *
     * @see #put(InputStream, String, SftpProgressMonitor, Mode)
     */
    default void put(@NonNull final InputStream src,
                     @NonNull final String dst,
                     @Nullable final SftpProgressMonitor monitor)
            throws SftpException {
        put(src, dst, monitor, Mode.Overwrite);
    }

    /**
     * Starts an upload from an OutputStream using {@link Mode#Overwrite}.
     *
     * @param dst the remote destination file name, relative to the
     *            <a href="#current-directory">current remote directory</a>.
     *
     * @return an OutputStream to which the application should write the file contents.
     *
     * @see #put(String, SftpProgressMonitor, Mode, long)
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
     *             <a href="#current-directory">current remote directory</a>.
     * @param mode the transfer {@link Mode}
     *
     * @return an OutputStream to which the application should write the file contents.
     *
     * @see #put(String, SftpProgressMonitor, Mode, long)
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
     * @param dst     the remote destination file name, relative to the
     *                <a href="#current-directory">current remote directory</a>.
     * @param monitor (optional) progress listener
     * @param mode    the transfer {@link Mode}
     *
     * @return an OutputStream to which the application should write the file contents.
     *
     * @see #put(String, SftpProgressMonitor, Mode, long)
     */
    @NonNull
    default OutputStream put(@NonNull final String dst,
                             @Nullable final SftpProgressMonitor monitor,
                             @NonNull final Mode mode)
            throws SftpException {
        return put(dst, monitor, mode, 0);
    }

    /**
     * Uploads a file using {@link Mode#Overwrite}.
     *
     * @param src the local source file name, absolute or relative to the
     *            <a href="#current-directory">current local directory</a>.
     * @param dst the remote destination file name, absolute or relative to the
     *            <a href="#current-directory">current remote directory</a>.
     *
     * @see #put(String, String, SftpProgressMonitor, Mode)
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
     *             <a href="#current-directory">current local directory</a>.
     * @param dst  the remote destination file name, absolute or relative to the
     *             <a href="#current-directory">current remote directory</a>.
     * @param mode the transfer {@link Mode}
     *
     * @see #put(String, String, SftpProgressMonitor, Mode)
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
     * @param src     the local source file name, absolute or relative to the
     *                <a href="#current-directory">current local directory</a>.
     * @param dst     the remote destination file name, absolute or relative to the
     *                <a href="#current-directory">current remote directory</a>.
     * @param monitor (optional) progress listener
     *
     * @see #put(String, String, SftpProgressMonitor, Mode)
     */
    default void put(@NonNull final String src,
                     @NonNull final String dst,
                     @Nullable final SftpProgressMonitor monitor)
            throws SftpException {
        put(src, dst, monitor, Mode.Overwrite);
    }

    /**
     * Starts an upload by OutputStream.
     * <p>
     * The returned output stream should be used by the application to
     * write data, which will then be uploaded to the remote file.
     * Closing the stream will finish the upload.
     *
     * @param dstPath the remote destination file name, relative to the
     *                <a href="#current-directory">current remote directory</a>.
     * @param monitor (optional) progress listener
     * @param mode    the transfer {@link Mode}
     * @param offset  the position in the remote file where we want to start writing.
     *                In the {@link Mode#Resume} and {@link Mode#Append}
     *                modes, this is added to the current size of the file
     *                (i.e. an offset > 0 creates a sparse section of that
     *                size in the file).
     *
     * @return an OutputStream to which the application should write the file contents.
     */
    @NonNull
    OutputStream put(@NonNull String dstPath,
                     @Nullable SftpProgressMonitor monitor,
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
     * @param srcFilename the local source file name, absolute or relative to the
     *                    <a href="#current-directory">current local directory</a>.
     * @param dstPath     the remote destination file name, absolute or relative to the
     *                    <a href="#current-directory">current remote directory</a>.
     * @param monitor     (optional) progress listener
     * @param mode        the transfer {@link Mode}
     */
    void put(@NonNull String srcFilename,
             @NonNull String dstPath,
             @Nullable SftpProgressMonitor monitor,
             @NonNull Mode mode)
            throws SftpException;

    /**
     * Uploads a file from an input stream.
     *
     * @param srcStream the source file, in the form of an input stream.
     * @param dstPath   the remote destination file name, relative to the
     *                  <a href="#current-directory">current remote directory</a>.
     * @param monitor   (optional) progress listener
     * @param mode      the transfer {@link Mode}
     */
    void put(@NonNull InputStream srcStream,
             @NonNull String dstPath,
             @Nullable SftpProgressMonitor monitor,
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
    interface SftpProgressMonitor {

        /**
         * Direction constant for upload.
         */
        int PUT = 0;
        /**
         * Direction constant for download.
         */
        int GET = 1;

        long UNKNOWN_SIZE = -1L;

        /**
         * Will be called when a new operation starts.
         *
         * @param op   a code indicating the direction of transfer,
         *             one of {@link #PUT} and {@link #GET}
         * @param src  the source file name.
         * @param dest the destination file name.
         * @param max  the final count (i.e. length of file to transfer).
         */
        void init(int op,
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
}
