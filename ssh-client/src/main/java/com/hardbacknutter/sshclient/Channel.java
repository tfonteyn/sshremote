package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public interface Channel {

    /**
     * Opens the channel without any timeout.
     * This is equivalent to {@link #connect(int) connect(0)}.
     *
     * @throws SshChannelException if any errors occur
     */
    default void connect()
            throws SshChannelException, GeneralSecurityException, IOException {
        connect(0);
    }

    /**
     * Opens the channel.
     *
     * @param connectTimeout the maximum time to wait for the channel to be
     *                       established, in milliseconds. If 0, we wait as long
     *                       as needed (but at most 1000 times 50 milliseconds each).
     *
     * @throws SshChannelException if any errors occur
     */
    void connect(final int connectTimeout)
            throws SshChannelException, GeneralSecurityException, IOException;

    /**
     * Disconnects the channel from the SSH server and cleans up any open resources.
     * Calling this method when the channel is not connected has no effect.
     */
    void disconnect();

    /**
     * Get the LOCAL channel id.
     *
     * @return local channel id
     */
    int getId();

    /**
     * Handle an incoming packet meant for this channel.
     *
     * @param packet to handle
     */
    void handle(@NonNull Packet packet)
            throws IOException, GeneralSecurityException;


    /**
     * Sets the InputStream for this channel. The channel
     * will then read from this stream and forward the data
     * in SSH_MSG_CHANNEL_DATA to the remote side.
     * This method should be called before {@link #connect}.
     *
     * @param do_not_close if {@code true}, we do not close the stream
     *                     when {@link #disconnect()} is called
     */
    void setInputStream(@NonNull InputStream in,
                        boolean do_not_close);

    /**
     * Gets an InputStream for this channel. All data arriving in
     * SSH_MSG_CHANNEL_DATA messages from the remote side can be
     * read from this stream.
     * <p>
     * This method is a polling alternative to {@link #setOutputStream}.
     * It should be called before {@link #connect}.
     */
    @NonNull
    InputStream getInputStream()
            throws IOException;

    /**
     * Sets the InputStream for this channel. The channel will
     * read from this stream and forward the data to the remote side.
     * The stream will be closed on {@link #disconnect}.
     * This method should be called before {@link #connect}.
     */
    default void setInputStream(@NonNull final InputStream in) {
        setInputStream(in, false);
    }


    /**
     * Gets an OutputStream for this channel.
     * <p>
     * All data written to this stream will be sent in
     * {@link SshConstants#SSH_MSG_CHANNEL_DATA} messages to the remote side.
     * <p>
     * This method is an alternative to {@link #setInputStream}.
     * It should be called before {@link #connect}.
     */
    @NonNull
    OutputStream getOutputStream();

    /**
     * Sets the OutputStream for this channel. All data arriving in
     * SSH_MSG_CHANNEL_DATA messages from the remote side will be
     * written to this OutputStream.
     * This method should be called before {@link #connect}.
     * The stream will be closed on {@link #disconnect}.
     *
     * @see #getInputStream
     */
    default void setOutputStream(@NonNull final OutputStream out) {
        setOutputStream(out, false);
    }

    /**
     * Sets the OutputStream for this channel. All data arriving in
     * SSH_MSG_CHANNEL_DATA messages from the remote side will be
     * written to this OutputStream.
     * This method should be called before {@link #connect}.
     *
     * @param do_not_close if {@code true}, we do not close the stream
     *                     on {@link #disconnect}.
     *
     * @see #getInputStream
     */
    void setOutputStream(@NonNull OutputStream out,
                         boolean do_not_close);


    /**
     * Gets an InputStream for extended data of this channel.
     * <p>
     * All data arriving in SSH_MSG_CHANNEL_EXTENDED_DATA messages
     * from the remote side can be read from this stream.
     * <p>
     * This method is a polling alternative to {@link #setExtOutputStream}.
     * It should be called before {@link #connect}.
     */
    @NonNull
    InputStream getExtInputStream()
            throws IOException;

    /**
     * Sets the OutputStream for extended data for this channel.
     * All data arriving in SSH_MSG_CHANNEL_EXTENDED_DATA messages
     * from the remote side will be written to this OutputStream.
     * <p>
     * <em>Note:</em> This implementation does not differentiate between
     * different 'data_type_code' values, as
     * <a href="http://https://datatracker.ietf.org/doc/html/rfc4254#section-5.2">
     * RFC 4254</a> only defines one type, namely SSH_EXTENDED_DATA_STDERR.
     * </p>
     * This method should be called before {@link #connect}.
     * <p>
     * The stream will be closed on {@link #disconnect}.
     *
     * @see #getExtInputStream
     */
    default void setExtOutputStream(@NonNull final OutputStream out) {
        setExtOutputStream(out, false);
    }

    /**
     * Sets the OutputStream for extended data for this channel.
     * All data arriving in SSH_MSG_CHANNEL_EXTENDED_DATA messages
     * from the remote side will be written to this OutputStream.
     *
     * <em>Note:</em> This implementation does not differentiate between
     * different 'data_type_code' values, as RFC 4254 only defines one type,
     * namely SSH_EXTENDED_DATA_STDERR.
     * </p>
     * This method should be called before {@link #connect}.
     *
     * @param do_not_close if {@code true}, we do not close the stream
     *                     on {@link #disconnect}.
     *
     * @see #getExtInputStream
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-5.2">
     * RFC 4254 SSH Connection Protocol, section 5.2: Data Transfer</a>
     */
    void setExtOutputStream(@NonNull OutputStream out,
                            boolean do_not_close);
}
