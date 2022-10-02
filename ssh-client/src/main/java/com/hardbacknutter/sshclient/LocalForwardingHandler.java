package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.forwarding.LocalForwardConfig;
import com.hardbacknutter.sshclient.forwarding.PortForwardException;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.List;

import javax.net.ServerSocketFactory;

/**
 * Handles all local port forwarding.
 * <p>
 * Has a 1:1 relation to an open Session.
 * <p>
 * Call {@link Session#getLocalForwardingHandler()} to gain access.
 */
@SuppressWarnings("unused")
public interface LocalForwardingHandler {

    /**
     * Lists the registered local port forwarding.
     *
     * @return a list local ports which are forwarded.
     */
    @NonNull
    List<LocalForwardConfig> getList();

    /**
     * Specifies that connections to the given TCP port on the local (client)
     * host are to be forwarded to the given host and port, on the remote side.
     * <p>
     * Equivalent to {@code ssh -L [bind_address:]port:host:hostport}
     *
     * @param connectionString in the format like "[bind_address:]port:host:hostport".
     *                         If {@code bindAddress} is an empty string or {@code "*"},
     *                         the port should be available from all interfaces.
     *                         If {@code bindAddress} is {@code "localhost"} or is not given,
     *                         the listening port will be bound for local use only.
     *
     * @return the allocated local port number
     */
    int add(@NonNull String connectionString)
            throws PortForwardException, IOException;

    /**
     * Same as {@link #add(String)} but all arguments separately
     * and a possibility to set a {@link ServerSocketFactory} and the connection timeout.
     *
     * @param bindAddress    (optional) bind address
     * @param localPort      local port
     * @param ssf            (optional) server socket factory
     * @param connectTimeout timeout for establishing connections
     * @param host           host address
     * @param remotePort     remote port
     *
     * @return the allocated local port number
     */
    int add(@Nullable String bindAddress,
            int localPort,
            @Nullable ServerSocketFactory ssf,
            int connectTimeout,
            @NonNull String host,
            int remotePort)
            throws PortForwardException, IOException;

    int add(@Nullable String bindAddress,
            int localPort,
            @Nullable ServerSocketFactory ssf,
            int connectTimeout,
            @NonNull String socketPath)
            throws PortForwardException, IOException;

    /**
     * Registers the local port forwarding for loop-back interface.
     * If {@code localPort} is {@code 0}, the tcp port will be allocated.
     *
     * @param localPort  local port for local port forwarding
     * @param host       host address for local port forwarding
     * @param remotePort remote port number for local port forwarding
     *
     * @return an allocated local TCP port number
     *
     * @see #add(String, int, ServerSocketFactory, int, String, int)
     */
    default int add(final int localPort,
                    @NonNull final String host,
                    final int remotePort)
            throws PortForwardException, IOException {
        return add(null, localPort, null, 0, host, remotePort);
    }

    /**
     * Registers the local port forwarding.
     * <p>
     * If {@code bindAddress} is an empty string
     * or '*', the port should be available from all interfaces.
     * If {@code bindAddress} is {@code "localhost"} or
     * {@code null}, the listening port will be bound for local use only.
     * If {@code localPort} is {@code 0}, the tcp port will be allocated.
     *
     * @param bindAddress bind address for local port forwarding
     * @param localPort   local port for local port forwarding
     * @param host        host address for local port forwarding
     * @param remotePort  remote port number for local port forwarding
     *
     * @return an allocated local TCP port number
     *
     * @see #add(String, int, ServerSocketFactory, int, String, int)
     */
    default int add(@Nullable final String bindAddress,
                    final int localPort,
                    @NonNull final String host,
                    final int remotePort)
            throws PortForwardException, IOException {
        return add(bindAddress, localPort, null, 0, host, remotePort);
    }

    /**
     * Registers the local port forwarding.
     * <p>
     * If {@code bindAddress} is an empty string or {@code "*"},
     * the port should be available from all interfaces.
     * If {@code bindAddress} is {@code "localhost"} or
     * {@code null}, the listening port will be bound for local use only.
     * If {@code localPort} is {@code 0}, the tcp port will be allocated.
     *
     * @param bindAddress bind address for local port forwarding
     * @param localPort   local port for local port forwarding
     * @param ssf         socket factory
     * @param host        host address for local port forwarding
     * @param remotePort  remote port number for local port forwarding
     *
     * @return an allocated local TCP port number
     *
     * @see #add(String, int, ServerSocketFactory, int, String, int)
     */
    default int add(@Nullable final String bindAddress,
                    final int localPort,
                    @Nullable final ServerSocketFactory ssf,
                    @NonNull final String host,
                    final int remotePort)
            throws PortForwardException, IOException {
        return add(bindAddress, localPort, ssf, 0, host, remotePort);
    }

    /**
     * Cancels the local port forwarding assigned
     * at local TCP port {@code localPort} on the loopback interface.
     *
     * @param localPort local TCP port
     */
    default void remove(final int localPort)
            throws UnknownHostException, PortForwardException {
        remove(null, localPort);
    }

    /**
     * Cancels the local port forwarding assigned
     * at local TCP port {@code localPort} on {@code bindAddress} interface.
     *
     * @param bindAddress bind address of network interfaces
     * @param localPort   local TCP port
     */
    void remove(@Nullable String bindAddress,
                int localPort)
            throws UnknownHostException, PortForwardException;
}
