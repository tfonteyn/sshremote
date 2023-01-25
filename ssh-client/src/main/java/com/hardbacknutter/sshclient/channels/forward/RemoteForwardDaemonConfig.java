package com.hardbacknutter.sshclient.channels.forward;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.ForwardedTCPIPDaemon;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.channels.SshChannelException;

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
            final Class<? extends ForwardedTCPIPDaemon> c =
                    Class.forName(className).asSubclass(ForwardedTCPIPDaemon.class);
            final ForwardedTCPIPDaemon daemon = c.getDeclaredConstructor().newInstance();
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
