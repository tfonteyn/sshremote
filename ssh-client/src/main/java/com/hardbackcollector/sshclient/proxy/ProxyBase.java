package com.hardbackcollector.sshclient.proxy;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SocketFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

abstract class ProxyBase
        implements Proxy {

    @NonNull
    private final String proxy_host;
    private final int proxy_port;
    @Nullable
    protected InputStream in;
    @Nullable
    protected OutputStream out;
    @Nullable
    protected Socket socket;
    @Nullable
    protected String user;
    @SuppressWarnings("WeakerAccess")
    @Nullable
    protected byte[] passwd;
    @Nullable
    private SocketFactory socketFactory;

    /**
     * Constructor.
     *
     * @param defaultPort to use if none specified
     * @param proxy_host  in the form of "host:port" or "host"
     */
    ProxyBase(final int defaultPort,
              @NonNull final String proxy_host) {
        int port = defaultPort;
        String host = proxy_host;
        final int colonIndex = proxy_host.indexOf(':');
        if (colonIndex != -1) {
            try {
                host = proxy_host.substring(0, colonIndex);
                port = Integer.parseInt(proxy_host.substring(colonIndex + 1));
            } catch (final Exception ignore) {
            }
        }
        this.proxy_host = host;
        this.proxy_port = port;
    }

    ProxyBase(@NonNull final String proxy_host,
              final int proxy_port) {
        this.proxy_host = proxy_host;
        this.proxy_port = proxy_port;
    }

    /**
     * Sets the user name and password needed for authentication
     * to the proxy. This has no relation to any authentication on
     * the target server.
     * <p>
     * If the proxy needs authentication, this method should be called
     * before calling {@link #connect} (i.e. before passing the Proxy
     * object to the library).
     * This class supports the "No Authentication Required" method as well
     * as the "UserName/Password" method.
     * </p>
     *
     * @param user   the user name
     * @param passwd the password.
     */
    @Override
    public void setUserPasswd(@Nullable final String user,
                              @Nullable final String passwd) {
        this.user = user;
        this.passwd = passwd == null ? null : passwd.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void setSocketFactory(@Nullable final SocketFactory socketFactory) {
        this.socketFactory = socketFactory;
    }

    void initIO(@NonNull final SocketFactory socketFactory,
                final int timeout)
            throws IOException {
        if (this.socketFactory == null) {
            this.socketFactory = socketFactory;
        }

        try {
            socket = this.socketFactory.createSocket(proxy_host, proxy_port, timeout);
            in = this.socketFactory.getInputStream(socket);
            out = this.socketFactory.getOutputStream(socket);

            if (timeout > 0) {
                socket.setSoTimeout(timeout);
            }
            socket.setTcpNoDelay(true);

        } catch (final Exception e) {
            close();
            throw e;
        }
    }

    @NonNull
    @Override
    public InputStream getInputStream() {
        return Objects.requireNonNull(in);
    }

    @NonNull
    @Override
    public OutputStream getOutputStream() {
        return Objects.requireNonNull(out);
    }

    @NonNull
    @Override
    public Socket getSocket() {
        return Objects.requireNonNull(socket);
    }

    @Override
    public void close() {
        if (in != null) {
            try {
                in.close();
            } catch (final IOException ignore) {
            }
            in = null;
        }

        if (out != null) {
            try {
                out.close();
            } catch (final IOException ignore) {
            }
            out = null;
        }

        if (socket != null) {
            try {
                socket.close();
            } catch (final IOException ignore) {
            }
            socket = null;
        }
    }
}
