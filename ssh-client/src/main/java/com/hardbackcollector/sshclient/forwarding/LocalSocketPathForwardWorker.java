package com.hardbackcollector.sshclient.forwarding;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.channels.direct.ChannelDirectStreamLocal;
import com.hardbackcollector.sshclient.transport.SessionImpl;

import java.net.Socket;
import java.util.Objects;

import javax.net.ServerSocketFactory;

/**
 * Takes care of forwarding a local port to the remote
 */
class LocalSocketPathForwardWorker
        extends LocalForwardWorker {

    @Nullable
    private String socketPath;

    LocalSocketPathForwardWorker(@NonNull final SessionImpl session,
                                 @Nullable final String address,
                                 final int localPort,
                                 final int connectTimeout,
                                 @Nullable final ServerSocketFactory ssf) {
        super(session, address, localPort, connectTimeout, ssf);
    }

    @Nullable
    String getSocketPath() {
        return socketPath;
    }

    void setSocketPath(@NonNull final String socketPath) {
        this.socketPath = socketPath;
    }

    public void run() {
        try {
            while (thread != null) {
                // accept() blocks until a connection is made.
                final Socket socket = ss.accept();
                socket.setTcpNoDelay(true);

                Objects.requireNonNull(socketPath);

                final ChannelDirectStreamLocal channel = new ChannelDirectStreamLocal(session);

                channel.setSocketPath(socketPath);

                channel.setInputStream(socket.getInputStream());
                channel.setOutputStream(socket.getOutputStream());
                channel.connect(connectTimeout);
            }
        } catch (final Exception ignore) {
        }
        close();
    }
}
