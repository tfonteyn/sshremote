package com.hardbackcollector.sshclient.channels.forward;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ForwardedTCPIPDaemon;
import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.RemoteForwardingHandler;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.channels.io.PassiveInputStream;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;

import java.io.IOException;
import java.io.PipedOutputStream;
import java.net.Socket;

/**
 * A Channel created when a forwarded port at the remote side is connected.
 * <p>
 * i.e. this channel is opened by the REMOTE.
 * <p>
 * This is used internally to forward remote ports to local ports or to
 * {@link ForwardedTCPIPDaemon local daemons}.
 *
 * @see RemoteForwardingHandler
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-7.2">
 * RFC 4254 SSH Connection Protocol, section 7.2. TCP/IP Forwarding Channels</a>
 */
public class ChannelForwardedTCPIP
        extends ForwardingChannel {

    /** internal use-only channel. */
    public static final String NAME = "forwarded-tcpip";

    private static final int TIMEOUT_IN_MILLIS = 10_000;

    @Nullable
    private RemoteForwardConfig remoteForwardConfig;

    ChannelForwardedTCPIP(@NonNull final SessionImpl session) {
        super(NAME, session);

        connected = true;
    }

    @Override
    void onRemoteOpen(@NonNull final Packet packet)
            throws IOException, SshChannelException {
        super.onRemoteOpen(packet);

        final String bindAddress = packet.getJString();
        final int port = packet.getInt();

        packet.skipString(); // originator address  (e.g., "192.168.7.38")
        packet.getInt(); // originator port

        final Session session = getSession();

        // lookup our configuration
        remoteForwardConfig = RemoteForwardingHandlerImpl.find(session, bindAddress, port);
        if (remoteForwardConfig == null) {
            remoteForwardConfig = RemoteForwardingHandlerImpl.find(session, null, port);
        }

        if (remoteForwardConfig == null) {
            final String msg = bindAddress + ":" + port + " is not registered.";
            SshClient.getLogger().log(Logger.ERROR, () -> msg);
            throw new SshChannelException(msg);
        }
    }

    /**
     * The channel transfer loop.
     */
    @Override
    public void run() {
        // first create the daemon or socket
        try {
            if (remoteForwardConfig instanceof RemoteForwardDaemonConfig) {
                final ForwardedTCPIPDaemon daemon =
                        ((RemoteForwardDaemonConfig) remoteForwardConfig).createDaemon();

                final PipedOutputStream pout = new PipedOutputStream();
                setInputStream(new PassiveInputStream(pout, getDefaultInputBufferSize()));

                daemon.setChannel(this, getInputStream(), pout);
                new Thread(daemon).start();

            } else if (remoteForwardConfig instanceof RemoteForwardSocketConfig) {
                final Socket socket = ((RemoteForwardSocketConfig) remoteForwardConfig)
                        .createSocket(TIMEOUT_IN_MILLIS);
                socket.setTcpNoDelay(true);
                setInputStream(socket.getInputStream());
                setOutputStream(socket.getOutputStream());
            } else {
                throw new IllegalStateException();
            }

            // and tell the server we did.
            sendChannelOpenConfirmation();

        } catch (final Exception e) {
            sendChannelOpenFailure(SshConstants.SSH_OPEN_CONNECT_FAILED);
            disconnect();
            return;
        }

        // work...
        runDataTransferLoop();
    }
}
