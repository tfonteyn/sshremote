package com.hardbacknutter.sshclient.forwarding;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.channels.direct.ChannelDirectTCPIP;
import com.hardbacknutter.sshclient.transport.SessionImpl;

import java.net.Socket;
import java.util.Objects;

import javax.net.ServerSocketFactory;

/**
 * Takes care of forwarding a local port to the remote
 */
class LocalPortForwardWorker
        extends LocalForwardWorker {

    @Nullable
    private String host;
    private int remotePort = -1;

    LocalPortForwardWorker(@NonNull final SessionImpl session,
                           @Nullable final String address,
                           final int localPort,
                           final int connectTimeout,
                           @Nullable final ServerSocketFactory ssf) {
        super(session, address, localPort, connectTimeout, ssf);
    }

    @Nullable
    String getHost() {
        return host;
    }

    int getRemotePort() {
        return remotePort;
    }

    void setRemote(@NonNull final String remoteHost,
                   final int remotePort) {
        this.host = remoteHost;
        this.remotePort = remotePort;
    }

    public void run() {
        try {
            while (thread != null) {
                // accept() blocks until a connection is made.
                final Socket socket = ss.accept();
                socket.setTcpNoDelay(true);

                Objects.requireNonNull(host);

                final ChannelDirectTCPIP channel = new ChannelDirectTCPIP(session);

                channel.setHost(host);
                channel.setPort(remotePort);
                channel.setOriginatorIPAddress(socket.getInetAddress().getHostAddress());
                channel.setOriginatorPort(socket.getPort());

                channel.setInputStream(socket.getInputStream());
                channel.setOutputStream(socket.getOutputStream());
                channel.connect(connectTimeout);
            }
        } catch (final Exception ignore) {
        }
        close();
    }
}
