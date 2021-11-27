package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.forwarding.PortForwardException;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Handles all remote port forwarding.
 * <p>
 * Has a 1:1 relation to an open Session.
 * <p>
 * Call {@link Session#getRemoteForwardingHandler()} to gain access.
 */
@SuppressWarnings("unused")
public interface RemoteForwardingHandler {

    /**
     * Lists the registered remote port forwarding.
     *
     * @return a List of "rport:host:hostport"
     */
    @NonNull
    List<String> getList();

    /**
     * Same as {@link #add(String)} but all arguments separately
     * * and a possibility to set a {@link SocketFactory}.
     *
     * @param bindAddress   (optional) bind address
     * @param remotePort    remote port
     * @param host          host address
     * @param localPort     local port
     * @param socketFactory (optional) socket factory
     * @return the allocated remote port number
     */
    int add(@Nullable String bindAddress,
            int remotePort,
            @NonNull String host,
            int localPort,
            @Nullable SocketFactory socketFactory)
            throws IOException, GeneralSecurityException, SshChannelException;

    /**
     * Specifies that connections to the given TCP port on the remote (server)
     * host are to be forwarded to the local side.
     * <p>
     * The connection will use the {@link Session} socket factory.
     * <p>
     * ssh -R [bind_address:]port:host:hostport
     *
     * @param connectionString in the format like "[bind_address:]port:host:hostport".
     *                         If the bind address is not given, the default is to only
     *                         bind to loopback addresses.
     *                         If the bind address is {@code "*"} or an empty string,
     *                         then the forwarding is requested to listen on all interfaces.
     *                         Note that if {@code GatewayPorts} is {@code "no"} on the remote,
     *                         {@code "localhost"} is always used for bind address.
     *                         If the specified remote is {@code "0"},
     *                         the TCP port will be allocated on the remote.
     * @return the allocated remote port number
     */
    int add(@NonNull String connectionString)
            throws IOException, GeneralSecurityException,
            PortForwardException, SshChannelException;

    /**
     * Registers the remote port forwarding for the loopback interface
     * of the remote.
     *
     * @param remotePort remote port
     * @param host       host address
     * @param localPort  local port
     */
    default int add(final int remotePort,
                    @NonNull final String host,
                    final int localPort)
            throws IOException, GeneralSecurityException, SshChannelException {
        return add(null, remotePort, host, localPort, null);
    }

    /**
     * Registers the remote port forwarding.
     * If {@code bindAddress} is an empty string or {@code "*"},
     * the port should be available from all interfaces.
     * If {@code bindAddress} is {@code "localhost"} or is not given,
     * the listening port will be bound for local use only.
     * Note that if {@code GatewayPorts} is {@code "no"} on the
     * remote, {@code "localhost"} is always used as a bind address.
     *
     * @param bindAddress bind address
     * @param remotePort  remote port
     * @param host        host address
     * @param localPort   local port
     */
    default int add(@NonNull final String bindAddress,
                    final int remotePort,
                    @NonNull final String host,
                    final int localPort)
            throws IOException, GeneralSecurityException, SshChannelException {
        return add(bindAddress, remotePort, host, localPort, null);
    }

    /**
     * Registers the remote port forwarding for the loopback interface
     * of the remote.
     *
     * @param remotePort    remote port
     * @param host          host address
     * @param localPort     local port
     * @param socketFactory (optional) socket factory
     */
    default int add(final int remotePort,
                    @NonNull final String host,
                    final int localPort,
                    @Nullable final SocketFactory socketFactory)
            throws IOException, GeneralSecurityException, SshChannelException {
        return add(null, remotePort, host, localPort, socketFactory);
    }

    /**
     * Registers the remote port forwarding.
     * If {@code bindAddress} is an empty string
     * or {@code "*"}, the port should be available from all interfaces.
     * If {@code bindAddress} is {@code "localhost"} or is not given,
     * the listening port will be bound for local use only.
     * Note that if {@code GatewayPorts} is {@code "no"} on the
     * remote, {@code "localhost"} is always used as a bind address.
     * The TCP connection to {@code remotePort} on the remote will be
     * forwarded to an instance of the class {@code daemon} with the
     * argument {@code arg}.
     * The class specified by {@code daemon} must implement {@code ForwardedTCPIPDaemon}.
     *
     * @param bindAddress bind address
     * @param remotePort  remote port
     * @param daemon      class name, which implements "ForwardedTCPIPDaemon"
     * @param arg         arguments for "daemon"
     */
    int addDaemon(@Nullable String bindAddress,
                  int remotePort,
                  @NonNull String daemon,
                  @Nullable Object[] arg)
            throws IOException, GeneralSecurityException, SshChannelException;

    /**
     * Registers the remote port forwarding for the loopback interface
     * of the remote.
     * The TCP connection to {@code remotePort} on the remote will be
     * forwarded to an instance of the class {@code daemon}.
     * The class specified by {@code daemon} must implement
     * {@code ForwardedTCPIPDaemon}.
     *
     * @param remotePort remote port
     * @param daemon     class name, which implements "ForwardedTCPIPDaemon"
     * @see #addDaemon(String, int, String, Object[])
     */
    default int addDaemon(final int remotePort,
                          @NonNull final String daemon)
            throws IOException, GeneralSecurityException, SshChannelException {
        return addDaemon(null, remotePort, daemon, null);
    }

    /**
     * Registers the remote port forwarding for the loopback interface
     * of the remote.
     * The TCP connection to {@code remotePort} on the remote will be
     * forwarded to an instance of the class {@code daemon} with
     * the argument {@code arg}.
     * The class specified by {@code daemon} must implement {@code ForwardedTCPIPDaemon}.
     *
     * @param remotePort remote port
     * @param daemon     class name, which implements "ForwardedTCPIPDaemon"
     * @param arg        arguments for "daemon"
     * @see #addDaemon(String, int, String, Object[])
     */
    default int addDaemon(final int remotePort,
                          @NonNull final String daemon,
                          @Nullable final Object[] arg)
            throws IOException, GeneralSecurityException, SshChannelException {
        return addDaemon(null, remotePort, daemon, arg);
    }

    /**
     * Cancels the remote port forwarding assigned at remote TCP port
     * {@code remotePort} bound on the interface at {@code bindAddress}.
     *
     * @param bindAddress bind address of the interface on the remote
     * @param remotePort  remote TCP port
     */
    void remove(@Nullable String bindAddress,
                int remotePort);

    /**
     * Cancels the remote port forwarding assigned at remote TCP port {@code remotePort}.
     *
     * @param remotePort remote TCP port
     */
    default void remove(final int remotePort) {
        remove(null, remotePort);
    }
}
