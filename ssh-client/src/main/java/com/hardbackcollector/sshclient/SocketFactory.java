package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * A factory for (client) sockets.
 * This works similar to {@link javax.net.SocketFactory}, but with the
 * ability to replace/wrap the Streams without having to subclass {@link Socket}
 * <p>
 * An application may pass an implementation of this interface to
 * the Session to control the creation of outgoing Sockets for
 * port forwarding (to other hosts/ports on the local side) or for
 * the main connection to the remote host.
 *
 * @see Session#setSocketFactory
 */
public interface SocketFactory {

    /**
     * Creates a Socket connected to a given host/port.
     *
     * @param host the destination host name.
     * @param port the destination port number.
     */
    @NonNull
    Socket createSocket(@NonNull String host,
                        int port)
            throws IOException;

    /**
     * Creates a Socket connected to a given host/port using the given timeout.
     * <p>
     * The default implementation <strong>ignores</strong> the {@code timeoutInMillis} parameter.
     *
     * @param host            the destination host name.
     * @param port            the destination port number.
     * @param timeoutInMillis to use.
     */
    @NonNull
    default Socket createSocket(@NonNull final String host,
                                final int port,
                                final int timeoutInMillis)
            throws IOException {
        return createSocket(host, port);
    }

    /**
     * Creates an {@link InputStream} for a {@link Socket}.
     * <p>
     * The default implementation simply calls {@code return socket.getInputStream()},
     * but advanced implementations may wrap the stream.
     *
     * @param socket a {@link Socket} created with {@link #createSocket}.
     *
     * @return an {@link InputStream} reading from the socket.
     */
    @NonNull
    default InputStream getInputStream(@NonNull final Socket socket)
            throws IOException {
        return socket.getInputStream();
    }

    /**
     * Creates an {@link OutputStream} for a {@link Socket}.
     * <p>
     * The default implementation simply calls {@code return socket.getOutputStream()},
     * but advanced implementations may wrap the stream.
     *
     * @param socket a {@link Socket} created with {@link #createSocket}.
     *
     * @return an {@link OutputStream} writing to the socket.
     */
    @NonNull
    default OutputStream getOutputStream(@NonNull final Socket socket)
            throws IOException {
        return socket.getOutputStream();
    }
}
