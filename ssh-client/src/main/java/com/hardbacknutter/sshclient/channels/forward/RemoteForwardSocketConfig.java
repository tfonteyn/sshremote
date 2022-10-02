package com.hardbacknutter.sshclient.channels.forward;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SocketFactory;

import java.io.IOException;
import java.net.Socket;

public class RemoteForwardSocketConfig
        extends RemoteForwardConfig {

    @NonNull
    private final String host;
    private final int localPort;
    @NonNull
    private final SocketFactory socketFactory;

    RemoteForwardSocketConfig(@NonNull final Session session,
                              final int remotePort,
                              final int allocatedRemotePort,
                              @NonNull final String bindAddress,
                              @NonNull final String host,
                              final int localPort,
                              @Nullable final SocketFactory socketFactory) {
        super(session, remotePort, allocatedRemotePort, bindAddress);

        this.host = host;
        this.localPort = localPort;
        this.socketFactory = socketFactory != null ? socketFactory : session.getSocketFactory();
    }

    @NonNull
    Socket createSocket(@SuppressWarnings("SameParameterValue") final int timeoutInMillis)
            throws IOException {
        return socketFactory.createSocket(host, localPort, timeoutInMillis);
    }

    @NonNull
    @Override
    public String getAsString() {
        return getAllocatedRemotePort() + ":" + host + ":" + localPort;
    }
}
