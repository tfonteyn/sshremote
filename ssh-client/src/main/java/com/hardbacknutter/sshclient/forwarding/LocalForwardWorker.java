package com.hardbacknutter.sshclient.forwarding;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import javax.net.ServerSocketFactory;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.transport.SessionImpl;

abstract class LocalForwardWorker {

    @NonNull
    final SessionImpl session;
    final int connectTimeout;
    @Nullable
    private final String address;
    @Nullable
    private final ServerSocketFactory ssf;
    @Nullable
    Thread thread;
    ServerSocket ss;
    private int localPort;
    private InetAddress bindAddress;

    LocalForwardWorker(@NonNull final SessionImpl session,
                       @Nullable final String address,
                       final int localPort,
                       final int connectTimeout,
                       @Nullable final ServerSocketFactory ssf) {
        this.session = session;

        this.address = address;
        this.localPort = localPort;
        this.connectTimeout = connectTimeout;
        this.ssf = ssf;
    }

    @NonNull
    Session getSession() {
        return session;
    }

    @NonNull
    InetAddress getBindAddress() {
        return bindAddress;
    }

    int getLocalPort() {
        return localPort;
    }

    /**
     * Start this PortWatcher as a thread listening and forwarding.
     *
     * @param asDaemon whether to start the thread as a daemon of not.
     *
     * @see Thread#setDaemon(boolean)
     */
    void start(final boolean asDaemon)
            throws IOException {
        @NonNull final InetAddress tmpAddress = InetAddress.getByName(address);
        ss = (ssf == null) ? new ServerSocket(localPort, 0, tmpAddress)
                : ssf.createServerSocket(localPort, 0, tmpAddress);

        if (localPort == 0) {
            final int assigned = ss.getLocalPort();
            if (assigned != -1) {
                localPort = assigned;
            }
        }
        bindAddress = tmpAddress;

        thread = new Thread(this::run);
        thread.setName("PortWatcher Thread for " + localPort);
        if (asDaemon) {
            thread.setDaemon(true);
        }
        thread.start();
    }

    protected abstract void run();

    void close() {
        // Signal to run() to quit looping
        thread = null;
        try {
            ss.close();
            //noinspection DataFlowIssue
            ss = null;
        } catch (final Exception ignore) {
        }
    }
}
