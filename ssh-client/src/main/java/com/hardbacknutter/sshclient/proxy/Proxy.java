package com.hardbacknutter.sshclient.proxy;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SocketFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Allows routing connections through some proxy.
 * <p>
 * A Proxy object creates a Socket and it's two streams for a remote
 * server. It typically does this by first connecting to a proxy server,
 * negotiating some conditions (or providing a password) and then returning
 * the streams as the connection will be forwarded to the target host.
 * </p>
 * <p>
 * The library (i.e. {@link Session}) uses a proxy only if given with
 * {@link Session#setProxy setProxy} before connecting. When connecting,
 * it will use the methods defined in this interface (except close), and
 * it will invoke {@link #close} on disconnecting.
 * </p>
 * <p>
 * Some implementing classes for common proxy types are delivered with
 * the library: {@link ProxyHTTP}, {@link ProxySOCKS4}, {@link ProxySOCKS5}.
 * An application might also create their own implementations and provide
 * these to the session before connecting.
 * </p>
 *
 * @see Session#setProxy
 */
public interface Proxy {

    /**
     * Sets the user name and password needed for authentication to the proxy.
     * This has no relation to any authentication on the target server.
     * <p>
     * If the proxy needs authentication, this method should be called
     * before calling {@link Session#connect}.
     *
     * @param user   the user name
     * @param passwd the password.
     */
    default void setUserPasswd(@Nullable final String user,
                               @Nullable final String passwd) {
        // see implementations
    }

    /**
     * Sets a custom SocketFactory for use by the Proxy.
     * If not set, or set to {@code null} the {@link Session} SocketFactory will be used.
     *
     * @param socketFactory to use
     */
    default void setSocketFactory(@Nullable final SocketFactory socketFactory) {
        // see implementations
    }

    /**
     * Opens a connection to the target server.
     * After successful invocation of this method the other methods
     * can be called to retrieve the results.
     *
     * @param host          the SSH server host we want to connect to.
     * @param port          the port at the SSH server.
     * @param timeout       how long to wait maximally for a connection, in
     *                      milliseconds. If {@code 0}, wait as long as needed.
     * @param socketFactory the current {@link Session} {@link SocketFactory}.
     *                      A Proxy implementation
     *                      <em>is free to ignore this and use a custom factory</em>
     *                      Also see {@link #setSocketFactory(SocketFactory)}.
     *
     * @throws IOException if it was not possible to create the connection to
     *                     the target host for some reason.
     */
    void connect(@NonNull String host,
                 int port,
                 int timeout,
                 @NonNull SocketFactory socketFactory)
            throws SshProxyException, IOException;


    /**
     * Returns an InputStream to read data from the remote server.
     * If the SSH protocol is tunneled through another protocol for
     * proxying purposes, this InputStream has to do the unwrapping.
     * <p>
     * Must only be called after a successful {@link #connect(String, int, int, SocketFactory)}.
     */
    @NonNull
    InputStream getInputStream();

    /**
     * Returns an OutputStream to write data to the remote server.
     * If the SSH protocol is tunneled through another protocol for
     * proxying purposes, this OutputStream has to do the wrapping.
     * <p>
     * Must only be called after a successful {@link #connect(String, int, int, SocketFactory)}.
     */
    @NonNull
    OutputStream getOutputStream();

    /**
     * Returns the socket used for the connection.
     * This will only be used for timeout-configurations.
     * <p>
     * Must only be called after a successful {@link #connect(String, int, int, SocketFactory)}.
     */
    @NonNull
    Socket getSocket();

    /**
     * Closes the connection. This should close the underlying socket as well.
     */
    void close();
}
