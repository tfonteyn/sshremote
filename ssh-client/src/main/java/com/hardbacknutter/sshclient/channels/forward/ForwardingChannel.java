package com.hardbacknutter.sshclient.channels.forward;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.channels.BaseChannel;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Base class for a channel which can be opened by the remote.
 */
public abstract class ForwardingChannel
        extends BaseChannel {

    ForwardingChannel(@NonNull final String type,
                      @NonNull final SessionImpl session) {
        super(type, session);
    }

    public static void openFromRemote(@NonNull final String type,
                                      @NonNull final SessionImpl session,
                                      @NonNull final Packet openRequest)
            throws SshChannelException, IOException {
        final ForwardingChannel channel;
        switch (type) {
            case ChannelAgentForwarding.NAME:
                channel = new ChannelAgentForwarding(session);
                break;

            case ChannelX11.NAME:
                channel = new ChannelX11(session);
                break;

            case ChannelForwardedTCPIP.NAME:
                // remote port forwarding
                channel = new ChannelForwardedTCPIP(session);
                break;

            default:
                throw new SshChannelException("Unknown channel type: " + type);
        }
        channel.setRecipient(openRequest.getInt());
        // initial window size
        channel.remoteWindowSize = openRequest.getUInt();
        channel.remoteMaxPacketSize = openRequest.getInt();
        channel.onRemoteOpen(openRequest);
        channel.startThread();
    }

    /**
     * The remote wants to open a channel.
     * <p>
     * Called after the common packet header fields are processed.
     * Override as needed.
     *
     * @see #sendChannelOpenConfirmation()
     * @see #sendChannelOpenFailure(int)
     */
    void onRemoteOpen(@NonNull final Packet packet)
            throws IOException, SshChannelException {
    }

    /**
     * Send a {@code SshConstants#SSH_MSG_CHANNEL_OPEN_CONFIRMATION} to the remote
     * indicating the channel was successfully opened.
     *
     * @see #onRemoteOpen(Packet)
     */
    void sendChannelOpenConfirmation()
            throws IOException, GeneralSecurityException {

        final Packet packet = new Packet(SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION)
                .putInt(getRecipient())
                .putInt(getId())
                .putInt(localWindowSize)
                .putInt(localMaxPacketSize);
        sendPacket(packet);
    }

    /**
     * Send a {@code SshConstants#SSH_MSG_CHANNEL_OPEN_FAILURE} to the remote
     * with the specified reason code.
     *
     * @param reasonCode to send to server
     *
     * @see #onRemoteOpen(Packet)
     */
    void sendChannelOpenFailure(final int reasonCode) {
        try {
            final Packet packet = new Packet(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE)
                    .putInt(getRecipient())
                    .putInt(reasonCode)
                    // description; will show in the sshd logs
                    .putString("Open failed")
                    // language tag
                    .putString("");
            sendPacket(packet);
        } catch (final Exception ignore) {
        }
    }
}
