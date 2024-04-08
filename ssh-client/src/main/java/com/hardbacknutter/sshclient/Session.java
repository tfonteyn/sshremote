package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.proxy.Proxy;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.SshException;

/**
 * 2021-06-02: initial introduction of a Session INTERFACE with the intention of
 * shielding internal methods. No doubt a number of methods *must* still be added here,
 * but it would be nice to split them up into several interfaces/objects.
 */
@SuppressWarnings("unused")
public interface Session {

    /**
     * Get the client this session belongs to.
     *
     * @return client
     */
    @NonNull
    SshClient getSshClient();

    /**
     * Sets the password to use for authentication.
     *
     * @param password the new password. (We will use the UTF-8 encoding
     *                 of this string as the actual password sent to the server.)
     *
     * @see #setPassword(byte[])
     */
    void setPassword(@Nullable String password);

    /**
     * Sets the password to use for authentication.
     * <p>
     * This will be used for the authentication methods
     * <ul>
     * <li>{@code password}, if it is not {@code null}</li>
     * <li>{@code keyboard-interactive} if it is not {@code null}, the prompt starts with
     *     {@code "password:"} and no UserInfo {@linkplain #setUserInfo is given}.</li>
     * </ul>
     *
     * @param password the new password.
     */
    void setPassword(@Nullable byte[] password);

    /**
     * Specifies an alias that should be used instead of the real host name
     * when looking up or saving the host key in the host key database files
     * and when validating host certificates.
     * <p>
     * This is useful when there are multiple SSH servers on a single host,
     * with different host keys.
     */
    void setHostKeyAlias(@NonNull String hostKeyAlias);

    /**
     * Get the current value of the UserInfo object.
     */
    @Nullable
    UserInfo getUserInfo();

    /**
     * Sets the userInfo property. If this is not {@code null}, the
     * UserInfo object is used for feedback to the user and to
     * query information from the user. Most important here is
     * the password query.
     */
    void setUserInfo(@Nullable UserInfo userinfo);

    /**
     * Sets a single configuration option for this session.
     *
     * @param key   the configuration key
     * @param value the configuration value.
     */
    void setConfig(@NonNull String key,
                   @NonNull String value);

    /**
     * Get access to all options as currently in use.
     *
     * @return the configuration
     */
    @NonNull
    SshClientConfig getConfig();

    /**
     * Sets several configuration options at once.
     *
     * @param newConf a Map, which should contain only String keys and values.
     *                All the current keys/value pairs are copied to the current configuration.
     *
     * @see #setConfig(String, String)
     */
    void setConfig(@NonNull Map<String, String> newConf);

    /**
     * Get the <em>resolved</em> host name used for connecting to the remote host.
     */
    @NonNull
    String getHost();

    /**
     * Get the port used for connecting to the remote host.
     */
    int getPort();


    /**
     * Opens the connection, using the timeout set with {@link #setTimeout}.
     *
     * @throws SshException if this session is already connected.
     * @see #connect(int)
     */
    void connect()
            throws SshException, IOException, GeneralSecurityException;

    /**
     * Opens the connection, using the specified timeout.
     *
     * @throws SshException     if this session is already connected, or some
     *                          other error occurs during connecting. (If there was some other
     *                          exception, it is chained as the cause)
     * @throws RuntimeException are thrown as-is
     */
    void connect(int connectTimeout)
            throws SshException, IOException, GeneralSecurityException;

    /**
     * Retrieves the current connection status.
     *
     * @return {@code true} if this session is connected, else {@code false}.
     */
    boolean isConnected();

    /**
     * Get the unique session id; only valid after key exchange (but before authentication)
     *
     * @return session id, or {@code null} if we have not exchanged keys yet
     */
    @Nullable
    byte[] getSessionId();

    /**
     * Get the host key of the server.
     * This is only valid after a successful {@link #connect}.
     *
     * @return the HostKey used by the remote host,
     *         or {@code null}, if we are not yet connected.
     */
    @Nullable
    HostKey getHostKey();

    /**
     * returns the current session {@link Logger}.
     *
     * @return the current logger
     */
    @NonNull
    Logger getLogger();

    /**
     * Override the {@link Logger} to be used by this session.
     *
     * @param logger the new logger. If {@code null}, we use a builtin
     *               Logger which logs nothing.
     */
    void setLogger(@Nullable Logger logger);

    /**
     * Creates a NEW ChannelSession instance of specified type.
     * <p>
     * Supported types:
     * <ul>
     *  <li>{@code shell} - {@link ChannelShell}</li>
     *  <li>{@code exec} - {@link ChannelExec}</li>
     *  <li>{@code sftp} - {@link ChannelSftp}</li>
     *
     *  <li>{@code subsystem} - {@link ChannelSubsystem}</li>
     *
     *  <li>{@code session} - {@link ChannelSession}</li>
     *  </ul>
     *
     * @param type a string identifying the channel type.
     *
     * @return a Channel of the requested type, initialized, but not yet connected.
     */
    @NonNull
    <T extends ChannelSession> T openChannel(@NonNull String type)
            throws SshChannelException, IOException;

    /**
     * Initiates a new key exchange. This is necessary for some changes on
     * the configuration to become active, like compression or encryption mode.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-9">
     *         RFC 4253 SSH Transport Layer Protocol, section 9.</a>
     */
    void rekey()
            throws IOException, GeneralSecurityException;

    /**
     * Send a {@code "keepalive"} message.
     * <p>
     * Used internally, but can be called by users when needed.
     */
    void sendKeepAlive()
            throws IOException, GeneralSecurityException;

    /**
     * Send a {@code SSH_MSG_IGNORE} message.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4251.html#section-9.3.1">
     *         RFC 4251 Protocol Architecture, section 9.3.1. (to avoid the Rogaway attack)</a>
     */
    void sendIgnore()
            throws IOException, GeneralSecurityException;

    /**
     * Send a global "no-more-sessions@openssh.com" message.
     *
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     *         SSH protocol version 2 vendor extensions, section 2.2</a>
     */
    void sendNoMoreSessions()
            throws IOException, GeneralSecurityException;

    /**
     * Closes the connection to the server.
     * If this session is not connected, this method is a no-op.
     */
    void disconnect();

    /**
     * retrieves the current timeout setting.
     *
     * @return timeout in milliseconds
     *
     * @see #setTimeout
     */
    int getTimeout();

    /**
     * Sets the timeout in milliseconds used on the socket connection to the
     * remote host.  A value of zero indicates no timeout.
     *
     * @param timeoutInMs in milliseconds
     *
     * @throws IOException if the existing socket timeout can't be changed.
     * @see java.net.Socket#setSoTimeout(int)
     */
    void setTimeout(int timeoutInMs)
            throws IOException;

    @NonNull
    SocketFactory getSocketFactory();

    /**
     * Sets the socket factory used to create a socket to the target host.
     * If not set, or set to {@code null}, we use plain TCP sockets.
     * <p>
     * Note that a separate socket factory can be passed to {@linkplain #setProxy proxy}.
     */
    void setSocketFactory(@Nullable SocketFactory factory);

    /**
     * Optionally sets a {@code Proxy} instance to tunnel the session through.
     * By default the proxy is {@code null}, indicating no proxying will be used.
     * <p>
     * Note: The proxy must be set prior to calling connect() if required.
     * <p>
     * Note: When the session is disconnected, the proxy connection is closed and
     * the proxy is set to {@code null}; it needs to be explicitly set again before
     * attempting to reconnect if it's required.
     *
     * @param proxy to use
     */
    void setProxy(@Nullable Proxy proxy);

    /**
     * Sets the daemon thread property.
     * <p>
     * This only affects threads started after the setting, so this
     * property should be set <strong>BEFORE</strong> calling {@link #connect}.
     * <p>
     * The default value is {@code false}.
     *
     * @param enable the new value of the property.
     *               If {@code true}, all threads will be daemon threads,
     *               i.e. their running does not avoid a shutdown of the VM.
     *               If {@code true}, normal non-daemon threads will be used (and the
     *               VM can only shutdown after {@link #disconnect} (or with
     *               {@link System#exit}).
     */
    void setRunAsDaemon(boolean enable);


    /**
     * Get the list of signature algorithms the server reported to support.
     *
     * @return list, will contain at least one element when available
     */
    @NonNull
    Optional<List<String>> getServerSignatureAlgorithms();

    /**
     * Gets the identityRepository.
     * If not set, {@link SshClient#getIdentityRepository()} will be returned.
     *
     * @see SshClient#getIdentityRepository()
     */
    @NonNull
    IdentityRepository getIdentityRepository();

    /**
     * Sets the identityRepository, which will be referred
     * in the public key authentication.
     * If not set, {@link SshClient#getIdentityRepository()} will be used.
     *
     * @see #getIdentityRepository()
     */
    void setIdentityRepository(@NonNull IdentityRepository identityRepository);


    /**
     * Gets the HostKeyRepository.
     * If not set, {@link SshClient#getHostConfigRepository()} will be returned.
     */
    @NonNull
    HostKeyRepository getHostKeyRepository();

    /**
     * Sets the HostKeyRepository, which will be referred in checking host keys.
     * If not set, {@link SshClient#getHostConfigRepository()} will be used.
     *
     * @see #getHostKeyRepository()
     */
    void setHostKeyRepository(@NonNull HostKeyRepository hostkeyRepository);

    /**
     * Get access to the local port forwarding handler.
     *
     * @return the handler.
     */
    @NonNull
    LocalForwardingHandler getLocalForwardingHandler();

    /**
     * Get access to the remote port forwarding handler.
     *
     * @return the handler.
     */
    @NonNull
    RemoteForwardingHandler getRemoteForwardingHandler();

    /**
     * Enable or disable ssh-agent forwarding.
     */
    void setAgentForwarding(boolean enable);

    /**
     * Enable or disable X11 forwarding.
     *
     * @param screenNumber a valid screen number to forward, or {@code -1} to disable
     */
    void setX11Forwarding(int screenNumber);

    /**
     * Set the host for the local X11 server.
     * <p>
     * The default value is {@code "127.0.0.1"}, i.e. the localhost
     * <p>
     * <em>Attention:</em> This is effectively a static property.
     * We're assuming/supporting only one local X11 server.
     *
     * @see #setX11Forwarding(int)
     * @see #setX11Port
     * @see #setX11Cookie
     */
    void setX11Host(@NonNull String host);

    /**
     * Set the port for the local X11 server.
     * <p>
     * The default value is 6000, the default port for a X11 server on display 0.
     * <p>
     * <em>Attention:</em> This is effectively a static property.
     * We're assuming/supporting only one local X11 server.
     *
     * @see #setX11Forwarding(int)
     * @see #setX11Host
     * @see #setX11Cookie
     */
    void setX11Port(int port);

    /**
     * Sets the X11 cookie necessary to access the local X11 server.
     * <p>
     * This implementation assumes the MIT-MAGIC_COOKIE-1 authentication protocol.
     * <p>
     * <em>Attention:</em> This is effectively a static property.
     * We're assuming/supporting only one local X11 server.
     *
     * @param cookie the cookie in hexadecimal encoding, should be 32 characters.
     *
     * @throws ArrayIndexOutOfBoundsException if the cookie is not 32 characters long
     * @see #setX11Forwarding(int)
     * @see #setX11Host
     * @see #setX11Port
     */
    void setX11Cookie(@NonNull String cookie);

    /**
     * returns the version string (to be) sent to the server.
     *
     * @return the client version string
     */
    @NonNull
    String getClientVersion();

    /**
     * Change the version string to be sent to the server.
     * <p>
     * The default is SSH 2.0 and the current library version.
     *
     * @param version the client version string. This will be encoded
     *                in the platform's default encoding. (A version string should
     *                normally only contain ASCII characters.)
     */
    void setClientVersion(@NonNull String version);

    /**
     * returns the version string as returned by the server.
     *
     * @return the server version string; only valid after a successful {@link #connect}.
     */
    @Nullable
    String getServerVersion();
}
