package com.hardbackcollector.sshclient.forwarding;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public final class LocalForwardConfig {

    /**
     * a {@code null} value == use the loopback device.
     */
    @Nullable
    public final String bindAddress;
    public final int port;

    /**
     * {@code null} if this Forwarding represents a socketPath
     */
    @Nullable
    public final String host;
    /**
     * {@code -1} if this Forwarding represents a socketPath
     */
    public final int hostPort;

    @Nullable
    public final String socketPath;

    /**
     * Used by {@link #parse(String)} to create a NEW {@link LocalPortForwardWorker}.
     */
    private LocalForwardConfig(@Nullable final String bindAddress,
                               final int port,
                               @NonNull final String host,
                               final int hostPort) {
        this.bindAddress = normalizeBindAddress(bindAddress);
        this.port = port;
        this.host = host;
        this.hostPort = hostPort;
        this.socketPath = null;
    }

    /**
     * Used by {@link #parse(String)} to create a NEW {@link LocalPortForwardWorker}.
     */
    private LocalForwardConfig(@Nullable final String bindAddress,
                               final int port,
                               @NonNull final String socketPath) {
        this.bindAddress = normalizeBindAddress(bindAddress);
        this.port = port;
        this.host = null;
        this.hostPort = -1;
        this.socketPath = socketPath;
    }

    /**
     * Used to provide the configuration of an EXISTING {@link LocalPortForwardWorker}.
     */
    LocalForwardConfig(@NonNull final LocalPortForwardWorker p) {
        this.bindAddress = p.getBindAddress().getHostAddress();
        this.port = p.getLocalPort();
        this.host = p.getHost();
        this.hostPort = p.getRemotePort();
        this.socketPath = null;
    }

    /**
     * Used to provide the configuration of an EXISTING {@link LocalSocketPathForwardWorker}.
     */
    LocalForwardConfig(@NonNull final LocalSocketPathForwardWorker p) {
        this.bindAddress = p.getBindAddress().getHostAddress();
        this.port = p.getLocalPort();
        this.host = null;
        this.hostPort = -1;
        this.socketPath = p.getSocketPath();
    }

    /**
     * From LocalForward command of ~/.ssh/config
     *
     * <pre>
     *      LocalForward
     *              Specifies that a TCP port on the local machine be forwarded over
     *              the secure channel to the specified host and port from the remote
     *              machine.  The first argument specifies the listener and may be
     *              [bind_address:]port or a Unix domain socket path.  The second
     *              argument is the destination and may be host:hostport or a Unix
     *              domain socket path if the remote host supports it.
     *  </pre>
     * <p>
     * "[bind_address:]port:host:hostport",
     * "[bind_address:]port host:hostport",
     * <p>
     * "[bind_address:]port:socketPath"
     * "[bind_address:]port socketPath"
     */
    public static LocalForwardConfig parse(@NonNull final String s)
            throws PortForwardException {

        final String[] args;
        if (s.contains(" ")) {
            //noinspection DynamicRegexReplaceableByCompiledPattern
            args = s.replaceAll(" ", ":").split(":");
        } else {
            args = s.split(":");
        }

        switch (args.length) {
            case 4: {
                try {
                    // "bind_address", "port", "host", "hostport"
                    final int port = Integer.parseInt(args[1]);
                    final int hostport = Integer.parseInt(args[3]);
                    return new LocalForwardConfig(args[0], port, args[2], hostport);
                } catch (final NumberFormatException ignore) {
                    // ignore
                }
                break;
            }
            case 3: {
                try {
                    // "port", "host", "hostport"
                    final int port = Integer.parseInt(args[0]);
                    final int hostport = Integer.parseInt(args[2]);
                    return new LocalForwardConfig(null, port, args[1], hostport);
                } catch (final NumberFormatException ignore) {
                    // Either we have a real port parsing issue, or we had a socketPath.
                }

                try {
                    // "bind_address", "port", "socketPath"
                    final int port = Integer.parseInt(args[1]);
                    return new LocalForwardConfig(args[0], port, args[2]);
                } catch (final NumberFormatException ignore) {
                    // ignore
                }
                break;
            }
            case 2: {
                try {
                    // "port", "socketPath"
                    final int port = Integer.parseInt(args[0]);
                    return new LocalForwardConfig(null, port, args[1]);
                } catch (final NumberFormatException ignore) {
                    // ignore
                }
                break;
            }
            default:
                break;
        }

        throw new PortForwardException("Parsing failed: '" + s + "'");
    }

    /**
     * An empty string or a {@code "*"} is simply substituted with ipV4 {@code 0.0.0.0}.
     * <p>
     * The string {@code "localhost"} is assumed to be ipV4 {@code 127.0.0.1}.
     * <p>
     * A {@code null} <strong>remains {@code null}</strong> which the Java API will
     * interpret as the 'local address'. Valid for ipV4 and ipV6.
     *
     * @param address to normalize
     * @return see above
     */
    @Nullable
    static String normalizeBindAddress(@Nullable final String address) {
        if (address != null) {
            if (address.isEmpty() || "*".equals(address)) {
                return "0.0.0.0";
            } else if ("localhost".equals(address)) {
                return "127.0.0.1";
            }
        }
        return address;
    }
}
