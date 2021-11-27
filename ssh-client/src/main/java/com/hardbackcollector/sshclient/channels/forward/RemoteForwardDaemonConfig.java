package com.hardbackcollector.sshclient.channels.forward;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ForwardedTCPIPDaemon;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.channels.SshChannelException;

import java.lang.reflect.InvocationTargetException;

public class RemoteForwardDaemonConfig
        extends RemoteForwardConfig {

    @NonNull
    private final String className;
    @Nullable
    private final Object[] args;

    RemoteForwardDaemonConfig(@NonNull final Session session,
                              final int remotePort,
                              final int allocatedRemotePort,
                              @NonNull final String bindAddress,
                              @NonNull final String className,
                              @Nullable final Object[] args) {
        super(session, remotePort, allocatedRemotePort, bindAddress);

        this.className = className;
        this.args = args;
    }

    @NonNull
    ForwardedTCPIPDaemon createDaemon()
            throws SshChannelException {
        try {
            final Class<?> c = Class.forName(className);
            final ForwardedTCPIPDaemon daemon = (ForwardedTCPIPDaemon) c
                    .getDeclaredConstructor().newInstance();
            daemon.setArgs(args);
            return daemon;

        } catch (final ClassNotFoundException | NoSuchMethodException | IllegalAccessException |
                InvocationTargetException | InstantiationException e) {
            throw new SshChannelException("Failed to create daemon", e);
        }
    }

    @NonNull
    @Override
    public String getAsString() {
        return getAllocatedRemotePort() + ":" + className + ":";
    }
}
