package com.hardbackcollector.sshclient.forwarding;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.LocalForwardingHandler;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.transport.SessionImpl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.net.ServerSocketFactory;

/**
 * Handles all local port forwarding.
 * <p>
 * Has a 1:1 relation to an open Session.
 * <p>
 * Call {@link Session#getLocalForwardingHandler()} to gain access.
 */
public class LocalForwardingHandlerImpl
        implements LocalForwardingHandler {

    private static final List<LocalForwardWorker> pool = new ArrayList<>();

    private static InetAddress anyLocalAddress;

    static {
        try {
            anyLocalAddress = InetAddress.getByName("0.0.0.0");
        } catch (final UnknownHostException ignore) {
        }
    }

    @NonNull
    private final SessionImpl session;

    /**
     * Constructor.
     */
    public LocalForwardingHandlerImpl(@NonNull final SessionImpl session) {
        this.session = session;
    }

    /**
     * Called when the session is disconnected.
     */
    public void disconnect() {
        synchronized (pool) {
            final List<LocalForwardWorker> list =
                    pool.stream()
                        .filter(pw -> ((Session) session).equals(pw.getSession()))
                        .collect(Collectors.toList());

            list.forEach(pw -> {
                pw.close();
                pool.remove(pw);
            });
        }
    }

    @Override
    @NonNull
    public List<LocalForwardConfig> getList() {
        final List<LocalForwardConfig> list = new ArrayList<>();

        synchronized (pool) {
            for (final LocalForwardWorker worker : pool) {
                if (worker.getSession().equals(session)) {
                    if (worker instanceof LocalPortForwardWorker) {
                        list.add(new LocalForwardConfig((LocalPortForwardWorker) worker));
                    } else if (worker instanceof LocalSocketPathForwardWorker) {
                        list.add(new LocalForwardConfig((LocalSocketPathForwardWorker) worker));
                    }
                }
            }
        }
        return list;
    }

    @Override
    public int add(@NonNull final String connectionString)
            throws PortForwardException, IOException {

        final LocalForwardConfig lfc = LocalForwardConfig.parse(connectionString);
        if (lfc.socketPath == null) {
            //noinspection ConstantConditions
            return add(lfc.bindAddress, lfc.port, null, 0, lfc.host, lfc.hostPort);
        } else {
            return add(lfc.bindAddress, lfc.port, null, 0, lfc.socketPath);
        }
    }

    @Override
    public int add(@Nullable final String bindAddress,
                   final int localPort,
                   @Nullable final ServerSocketFactory ssf,
                   final int connectTimeout,
                   @NonNull final String host,
                   final int remotePort)
            throws PortForwardException, IOException {

        final String address = LocalForwardConfig.normalizeBindAddress(bindAddress);

        if (find(localPort, address) != null) {
            throw new PortForwardException("local port " + address
                                                   + ":" + localPort + " is already registered.");
        }

        final LocalPortForwardWorker pw =
                new LocalPortForwardWorker(session, address, localPort, connectTimeout, ssf);
        pw.setRemote(host, remotePort);

        pw.start(session.isRunningAsDaemonThread());
        pool.add(pw);
        return pw.getLocalPort();
    }

    @Override
    public int add(@Nullable final String bindAddress,
                   final int localPort,
                   @Nullable final ServerSocketFactory ssf,
                   final int connectTimeout,
                   @NonNull final String socketPath)
            throws PortForwardException, IOException {

        if (socketPath.isEmpty()) {
            throw new PortForwardException("Socket path cannot be empty");
        }

        final String address = LocalForwardConfig.normalizeBindAddress(bindAddress);

        if (find(localPort, address) != null) {
            throw new PortForwardException("local port " + address
                                                   + ":" + localPort + " is already registered.");
        }

        final LocalSocketPathForwardWorker pw =
                new LocalSocketPathForwardWorker(session, address, localPort, connectTimeout, ssf);
        pw.setSocketPath(socketPath);

        pw.start(session.isRunningAsDaemonThread());
        pool.add(pw);
        return pw.getLocalPort();
    }

    @Override
    public void remove(@Nullable final String bindAddress,
                       final int localPort)
            throws UnknownHostException, PortForwardException {

        final String address = LocalForwardConfig.normalizeBindAddress(bindAddress);

        final LocalForwardWorker pw = find(localPort, address);
        if (pw == null) {
            throw new PortForwardException("local port " + address
                                                   + ":" + localPort + " is not registered.");
        }
        pw.close();
        pool.remove(pw);
    }

    /**
     * Return the instance for the given session/port (and optional bind address).
     *
     * @return the PortWatcher, or {@code null} if there wasn't one.
     */
    @Nullable
    private LocalForwardWorker find(final int localPort,
                                    @Nullable final String bindAddress)
            throws UnknownHostException {
        final InetAddress inetAddress = InetAddress.getByName(bindAddress);

        synchronized (pool) {
            return pool.stream()
                       .filter(pw -> session.equals(pw.getSession()))
                       .filter(pw -> localPort == pw.getLocalPort())
                       .filter(pw -> (anyLocalAddress.equals(pw.getBindAddress())
                               || pw.getBindAddress().equals(inetAddress)))
                       .findFirst()
                       .orElse(null);
        }
    }
}
