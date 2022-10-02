package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ChannelSftp;
import com.hardbacknutter.sshclient.channels.SshChannelException;

/**
 * This exception will be thrown if anything goes wrong while
 * using the SFTP protocol. The exception contains an error identifier,
 * which corresponds to the status codes used in the SFTP protocol
 * for error messages. The following values are used directly in the
 * source code:<dl>
 * <dt>{@link ChannelSftpImpl} SSH_FX_FAILURE</dt>
 * <dd>a general failure message.</dd>
 * <dt>{@link ChannelSftpImpl} SSH_FX_NO_SUCH_FILE</dt>
 * <dd>some file or directory was non-existent</dd>
 * <dt>{@link ChannelSftpImpl} SSH_FX_OP_UNSUPPORTED</dt>
 * <dd>some operation is not supported by the server</dd>
 * </dd>
 * But in general every SSH_FXP_STATUS status value can be thrown.
 *
 * @see ChannelSftp
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7">
 * Internet Draft "SSH File Transfer Protocol" (version 02 describing
 * version 3 of the protocol), section 7: Responses from the Server
 * to the Client</a>
 */
public class SftpException
        extends SshChannelException {

    private static final long serialVersionUID = -3009478811882398223L;

    /** The status code which caused the exception to be thrown. */
    private final int status;

    /**
     * Creates a new SftpException.
     *
     * @param status the status code identifying the type of error.
     */
    SftpException(final int status) {
        super("");
        this.status = status;
    }

    /**
     * Creates a new SftpException.
     *
     * @param status  the status code identifying the type of error.
     * @param message the error message sent by the server or generated
     *                by the client.
     */
    SftpException(final int status,
                  @Nullable final String message) {
        super(message);
        this.status = status;
    }

    /**
     * Creates a new SftpException.
     *
     * @param status the status code identifying the type of error.
     * @param e      a throwable which was the cause of this exception.
     *               May be {@code null} if there was no thrown cause.
     */
    SftpException(final int status,
                  @Nullable final Throwable e) {
        super(e);
        this.status = status;
    }

    /**
     * Creates a new SftpException.
     *
     * @param status  the status code identifying the type of error.
     * @param message the error message sent by the server or generated
     *                by the client.
     * @param e       a throwable which was the cause of this exception.
     *                May be {@code null} if there was no thrown cause.
     */
    @SuppressWarnings("unused")
    SftpException(final int status,
                  @Nullable final String message,
                  @Nullable final Throwable e) {
        super(message, e);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    /**
     * returns a String representation of this exception containing status and message.
     */
    public String getMessage() {
        return status + ": " + super.getMessage();
    }
}
