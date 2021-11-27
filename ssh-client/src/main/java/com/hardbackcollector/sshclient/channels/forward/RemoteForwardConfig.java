package com.hardbackcollector.sshclient.channels.forward;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.Session;

public abstract class RemoteForwardConfig {

    @NonNull
    private final Session session;
    private final int remotePort;
    private final int allocatedRemotePort;
    @NonNull
    private final String bindAddress;

    RemoteForwardConfig(@NonNull final Session session,
                        final int remotePort,
                        final int allocatedRemotePort,
                        @NonNull final String bindAddress) {
        this.session = session;
        this.remotePort = remotePort;
        this.allocatedRemotePort = allocatedRemotePort;
        this.bindAddress = bindAddress;
    }

    @NonNull
    public Session getSession() {
        return session;
    }

    int getRemotePort() {
        return remotePort;
    }

    int getAllocatedRemotePort() {
        return allocatedRemotePort;
    }

    @NonNull
    String getBindAddress() {
        return bindAddress;
    }

    @NonNull
    public abstract String getAsString();
}
