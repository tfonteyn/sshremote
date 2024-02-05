package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;

import com.hardbacknutter.sshclient.Channel;
import com.hardbacknutter.sshclient.ChannelExec;
import com.hardbacknutter.sshclient.ChannelSession;
import com.hardbacknutter.sshclient.ChannelSftp;
import com.hardbacknutter.sshclient.ChannelShell;
import com.hardbacknutter.sshclient.ChannelSubsystem;
import com.hardbacknutter.sshclient.LocalForwardingHandler;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.RemoteForwardingHandler;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SocketFactory;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.SshSessionConfig;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.channels.forward.ChannelAgentForwarding;
import com.hardbacknutter.sshclient.channels.forward.ChannelForwardedTCPIP;
import com.hardbacknutter.sshclient.channels.forward.ChannelX11;
import com.hardbacknutter.sshclient.channels.forward.ForwardingChannel;
import com.hardbacknutter.sshclient.channels.forward.RemoteForwardingHandlerImpl;
import com.hardbacknutter.sshclient.channels.session.ChannelExecImpl;
import com.hardbacknutter.sshclient.channels.session.ChannelSessionImpl;
import com.hardbacknutter.sshclient.channels.session.ChannelShellImpl;
import com.hardbacknutter.sshclient.channels.session.ChannelSubsystemImpl;
import com.hardbacknutter.sshclient.channels.sftp.ChannelSftpImpl;
import com.hardbacknutter.sshclient.forwarding.LocalForwardingHandlerImpl;
import com.hardbacknutter.sshclient.forwarding.PortForwardException;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.hostkey.KnownHosts;
import com.hardbacknutter.sshclient.identity.IdentityImpl;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.identity.IdentityRepositoryWrapper;
import com.hardbacknutter.sshclient.kex.KexAgreement;
import com.hardbacknutter.sshclient.kex.KexDelegate;
import com.hardbacknutter.sshclient.kex.KexException;
import com.hardbacknutter.sshclient.kex.KexKeys;
import com.hardbacknutter.sshclient.kex.KexTimeoutException;
import com.hardbacknutter.sshclient.proxy.Proxy;
import com.hardbacknutter.sshclient.userauth.SshAuthCancelException;
import com.hardbacknutter.sshclient.userauth.SshAuthException;
import com.hardbacknutter.sshclient.userauth.SshAuthNoSuchMethodException;
import com.hardbacknutter.sshclient.userauth.SshPartialAuthException;
import com.hardbacknutter.sshclient.userauth.UserAuth;
import com.hardbacknutter.sshclient.userauth.UserAuthNone;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.SshClientConfigImpl;
import com.hardbacknutter.sshclient.utils.SshConstants;
import com.hardbacknutter.sshclient.utils.SshException;

/**
 * A Session represents a connection to a SSH server.
 * <p>
 * A session is opened with {@link #connect()} and closed with {@link #disconnect}.
 * <p>
 * One session can contain multiple {@link Channel}s of various types,
 * created with {@link #openChannel} and closed with {@link Channel#disconnect()}
 */
public final class SessionImpl
        implements Session, PacketIO {

    /** All channels opened by this session. */
    private static final Map<Integer, Channel> channelPool =
            Collections.synchronizedMap(new HashMap<>());

    private static final byte[] MSG_KEEP_ALIVE = "keepalive@sshclient4j.com"
            .getBytes(StandardCharsets.UTF_8);

    private static final String ERROR_SESSION_IS_DOWN = "Session is not connected";

    @NonNull
    private final SshSessionConfig config;
    @NonNull
    private final SshClientImpl sshClient;
    @Nullable
    private final String username;
    @NonNull
    private final String host;
    private final int port;

    /** Separates all logic for handling forwarding of ports and sockets. */
    @Nullable
    private RemoteForwardingHandlerImpl remoteForwardingHandler;
    @Nullable
    private LocalForwardingHandlerImpl localForwardingHandler;

    private int x11Forwarding;
    private boolean agentForwarding;
    private boolean runAsDaemonThread;

    /** server version. */
    @Nullable
    private String serverVersion;

    /** client version. */
    @NonNull
    private String clientVersion = SshClientImpl.VERSION;

    /** Unique session id, based on the hash from the KeyExchange. */
    @Nullable
    private byte[] sessionId;

    @Nullable
    private TransportS2C s2c;
    @Nullable
    private TransportC2S c2s;
    @Nullable
    private byte[] password;
    @Nullable
    private UserInfo userinfo;
    @Nullable
    private String hostKeyAlias;
    @Nullable
    private SocketFactory socketFactory;
    @Nullable
    private Socket socket;
    @Nullable
    private Proxy proxy;
    /** milliseconds. */
    private int timeout;

    private boolean connected;
    private boolean authenticated;

    @Nullable
    private Thread sessionThread;
    private int serverAliveInterval;
    private int serverAliveCountMax = 1;

    /** Always use {@link #getIdentityRepository()}. */
    @Nullable
    private IdentityRepository identityRepository;
    /** Always use {@link #getHostKeyRepository()}. */
    @Nullable
    private HostKeyRepository hostKeyRepository;

    @Nullable
    private KexDelegate kexDelegate;
    @Nullable
    private List<String> serverSigAlgs;

    /**
     * Private constructor. Always use the static factory methods to get the correct type back.
     */
    private SessionImpl(@NonNull final SshClientImpl sshClient,
                        @Nullable final HostConfig hostConfig,
                        @Nullable final String username,
                        @NonNull final String hostnameOrAlias,
                        final int port)
            throws IOException, GeneralSecurityException, SshAuthException {

        this.sshClient = sshClient;
        // create a child config
        final SshClientConfig parentConfig = sshClient.getConfig();
        this.config = new SshClientConfigImpl(parentConfig, hostConfig, parentConfig.getLogger());

        this.username = resolveUsername(username, hostConfig);
        this.host = resolveHostname(hostnameOrAlias, hostConfig);
        this.hostKeyAlias = hostnameOrAlias;
        this.port = resolvePort(port, hostConfig);

        if (hostConfig != null) {
            applyHostConfig(hostConfig);
        }

        getLogger().log(Logger.INFO, () ->
                "Session created for " + username + "@" + hostnameOrAlias + ":" + port);
    }

    /**
     * INTERNAL USE ONLY.
     * <p>
     * Called from {@link SshClientImpl#getSession(String, String, int)}.
     *
     * @return a new Session
     */
    @NonNull
    static Session createSession(@NonNull final SshClientImpl sshClient,
                                 @Nullable final HostConfig hostConfig,
                                 @Nullable final String username,
                                 @NonNull final String hostnameOrAlias,
                                 final int port)
            throws GeneralSecurityException, IOException, SshAuthException {
        return new SessionImpl(sshClient, hostConfig, username, hostnameOrAlias, port);
    }

    @NonNull
    private String resolveUsername(@Nullable final String username,
                                   @Nullable final HostConfig hostConfig)
            throws SshAuthException {
        if (username != null && !username.isBlank()) {
            return username;
        }

        String resolved = null;
        if (hostConfig != null) {
            resolved = hostConfig.getUser();
        }
        if (resolved != null && !resolved.isBlank()) {
            return resolved;
        }

        try {
            resolved = System.getProperty("user.name");
            if (resolved != null && !resolved.isBlank()) {
                return resolved;
            }
        } catch (final SecurityException ignore) {
        }

        throw new SshAuthException("Username not available");
    }

    private String resolveHostname(@NonNull final String hostnameOrAlias,
                                   @Nullable final HostConfig hostConfig) {
        // The passed in host name can be an alias as used previously to lookup the HostConfig.
        // If the HostConfig has the real host name (or is identical) use that one.
        String resolved = null;
        if (hostConfig != null) {
            resolved = hostConfig.getHostname();
        }
        if (resolved != null && !resolved.isBlank()) {
            return resolved;
        }

        // must be an actual hostname
        return hostnameOrAlias;
    }

    private int resolvePort(final int port,
                            @Nullable final HostConfig hostConfig) {
        if (port > 0) {
            return port;
        }
        int resolved = 0;
        if (hostConfig != null) {
            resolved = hostConfig.getPort();
        }
        if (resolved > 0) {
            return resolved;
        }

        return 22;
    }

    @NonNull
    @Override
    public SshClient getSshClient() {
        return sshClient;
    }

    @Nullable
    public byte[] getPassword() {
        return password;
    }

    @Override
    public void setPassword(@Nullable final String password) {
        if (password != null) {
            this.password = password.getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public void setPassword(@Nullable final byte[] password) {
        if (password != null) {
            this.password = Arrays.copyOf(password, password.length);
        }
    }

    @Nullable
    public UserInfo getUserInfo() {
        return userinfo;
    }

    @Override
    public void setUserInfo(@Nullable final UserInfo userinfo) {
        this.userinfo = userinfo;
    }

    @Override
    @NonNull
    public SshClientConfig getConfig() {
        return config;
    }

    @Override
    public void setConfig(@NonNull final Map<String, String> newConf) {
        synchronized (config) {
            for (final Map.Entry<String, String> entry : newConf.entrySet()) {
                config.putString(entry.getKey(), entry.getValue());
            }
        }
    }

    @Override
    public void setConfig(@NonNull final String key,
                          @NonNull final String value) {
        synchronized (config) {
            config.putString(key, value);
        }
    }

    @Override
    public void setHostKeyAlias(@NonNull final String hostKeyAlias) {
        this.hostKeyAlias = hostKeyAlias;
    }

    @Override
    @NonNull
    public IdentityRepository getIdentityRepository() {
        return Objects.requireNonNullElseGet(identityRepository, sshClient::getIdentityRepository);
    }

    @Override
    public void setIdentityRepository(@NonNull final IdentityRepository identityRepository) {
        this.identityRepository = identityRepository;
    }

    @Override
    @NonNull
    public HostKeyRepository getHostKeyRepository() {
        return Objects.requireNonNullElseGet(hostKeyRepository, sshClient::getHostKeyRepository);
    }

    @Override
    public void setHostKeyRepository(@NonNull final HostKeyRepository hostkeyRepository) {
        this.hostKeyRepository = hostkeyRepository;
    }


    @Override
    public void connect()
            throws SshException, GeneralSecurityException, IOException {
        connect(timeout);
    }

    @Override
    public void connect(final int timeoutInMillis)
            throws SshException, GeneralSecurityException, IOException {
        if (connected) {
            throw new IOException("Session is already connected");
        }

        getLogger().log(Logger.INFO, () -> "Connecting to " + host + ":" + port);

        try {
            // Setup socket and input/output streams. Use a proxy if so configured.
            if (socketFactory == null) {
                socketFactory = new SocketFactoryImpl();
            }

            final InputStream socketInputStream;
            final OutputStream socketOutputStream;
            if (proxy == null) {
                socket = socketFactory.createSocket(host, port, timeoutInMillis);
                socket.setTcpNoDelay(true);
                socketInputStream = socketFactory.getInputStream(socket);
                socketOutputStream = socketFactory.getOutputStream(socket);

            } else {
                synchronized (proxy) {
                    proxy.connect(host, port, timeoutInMillis, socketFactory);
                    socket = proxy.getSocket();
                    socketInputStream = proxy.getInputStream();
                    socketOutputStream = proxy.getOutputStream();
                }
            }

            // Set the socket timeout for reads if timeout is greater than zero
            if (timeoutInMillis > 0 && socket != null) {
                socket.setSoTimeout(timeoutInMillis);
            }

            s2c = new TransportS2C(this, socketInputStream);
            c2s = new TransportC2S(this, socketOutputStream);

            connected = true;

            // Step 1: verify the client and server support each others version
            c2s.writeVersion(clientVersion);
            serverVersion = s2c.readVersion();

            // Step 2: the full KeyExchange to agree on
            kexDelegate = new KexDelegate(this, serverVersion, clientVersion,
                                          createHostKeyName());

            final KexKeys keys = kexDelegate.startExchange(getHostKeyRepository(), userinfo);
            takeKeysIntoUse(keys);

            // Step 3: the user must authenticate by a mutually agreed method
            doAuthentication();

            // Updates the socket timeout to the session timeout
            if (socket != null && (timeoutInMillis > 0 || timeout > 0)) {
                socket.setSoTimeout(timeout);
            }

            // Step 4: start this session as a Thread to handle all further communication
            synchronized (this) {
                if (connected) {
                    sessionThread = new Thread(this::run);
                    sessionThread.setName("Session to: " + host);
                    if (runAsDaemonThread) {
                        sessionThread.setDaemon(true);
                    }
                    sessionThread.start();

                    // add (start) the hostConfig forwards if allowed.
                    if (!config.getBooleanValue(HostConfig.CLEAR_ALL_FORWARDS, false)) {
                        initForwards();
                    }
                }
            }

            getLogger().log(Logger.INFO, () -> "Connection established");

        } catch (final GeneralSecurityException | IOException | SshException e) {
            cleanup(e);
            throw e;

        } catch (final Exception e) {
            cleanup(e);
            throw new KexException(e);

        } finally {
            if (this.password != null) {
                Arrays.fill(this.password, (byte) 0);
            }
            this.password = null;
        }
    }

    @NonNull
    private String createHostKeyName() {
        if (hostKeyAlias != null) {
            return hostKeyAlias;
        } else if (port != 22) {
            return "[" + host + "]:" + port;
        } else {
            return host;
        }
    }

    private void initForwards()
            throws IOException, GeneralSecurityException,
                   PortForwardException, SshChannelException {

        List<String> values;

        values = config.getStringList(HostConfig.LOCAL_FORWARD);
        if (!values.isEmpty()) {
            // get or create the #localForwardingHandler
            final LocalForwardingHandler handler = getLocalForwardingHandler();
            for (final String connectString : values) {
                handler.add(connectString);
            }
        }

        values = config.getStringList(HostConfig.REMOTE_FORWARD);
        if (!values.isEmpty()) {
            // get or create the #remoteForwardingHandler
            final RemoteForwardingHandler handler = getRemoteForwardingHandler();
            for (final String connectString : values) {
                handler.add(connectString);
            }
        }
    }

    private void cleanup(@NonNull final Exception e) {
        // paranoia
        if (kexDelegate != null) {
            kexDelegate.setKeyExchangeDone();
        }

        getLogger().log(Logger.DEBUG, e, () -> "KEX cleanup");

        try {
            // If things went wrong, but we are in fact connected, we need to tell the server
            if (connected) {
                final String description = e.toString();
                final Packet packet = new Packet(SshConstants.SSH_MSG_DISCONNECT)
                        .putInt(SshConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED)
                        .putString(description)
                        // language tag
                        .putString("");
                write(packet);
            }
        } catch (final Exception ignore) {
        }

        // cleanup all session related objects/connections
        disconnect();
    }


    /**
     * Connect step 3/3.
     */
    private void doAuthentication()
            throws IOException, GeneralSecurityException, SshException {

        Objects.requireNonNull(username, "No username set");

        // Use the 'none' class to exchange the actual auth methods
        // client and server can agree on.
        UserAuth ua = ImplementationFactory.getUserAuth(config, UserAuthNone.METHOD);
        ua.init(config, username, userinfo);
        // no password used here !
        boolean auth = ua.authenticate(this, this, null);

        final List<String> clientMethods = config
                .getStringList(HostConfig.PREFERRED_AUTHENTICATIONS);
        if (clientMethods.isEmpty()) {
            throw new SshAuthException("No client auth methods configured");
        }

        // Either read the server supported methods from the auth module,
        List<String> serverMethods = null;
        if (!auth && ua instanceof UserAuthNone) {
            serverMethods = ((UserAuthNone) ua).getMethods();
        }
        // or simply copy them over from the client.
        if (serverMethods == null || serverMethods.isEmpty()) {
            serverMethods = new ArrayList<>(clientMethods);
        }

        // Index into the list; count's up as expected,
        // but resets to 0 upon receiving a new set from the server
        int nextMethod = 0;

        String methodCanceled = null;

        // Try each auth method until we're authenticated or have run out of methods to try.
        while (!auth && nextMethod < clientMethods.size()) {

            // Is the current client method we want to try acceptable to the server ?
            final String method = clientMethods.get(nextMethod++);
            if (serverMethods.contains(method)) {

                if (getLogger().isEnabled(Logger.INFO)) {
                    final StringJoiner sj = new StringJoiner(
                            ",", "Authentications that can continue: ",
                            "; Next is: " + method);
                    for (int k = nextMethod - 1; k < clientMethods.size(); k++) {
                        sj.add(clientMethods.get(k));
                    }
                    getLogger().log(Logger.INFO, sj.toString());
                }

                try {
                    ua = ImplementationFactory.getUserAuth(config, method);
                    ua.init(config, username, userinfo);
                    auth = ua.authenticate(this, this, password);
                    if (auth) {
                        getLogger().log(Logger.INFO, () -> "Authentication success: " + method);
                        authenticated = true;
                        return;
                    }
                    methodCanceled = null;
                    // loop and try the next method.

                } catch (final SshPartialAuthException e) {
                    final List<String> tmp = serverMethods;
                    serverMethods = e.getMethods();
                    if (!tmp.equals(serverMethods)) {
                        nextMethod = 0;
                    }
                    methodCanceled = null;
                    // loop and try the next method.

                } catch (final SshAuthCancelException e) {
                    // THIS method cancelled; loop and try the next method.
                    methodCanceled = method;

                } catch (final SshAuthNoSuchMethodException e) {
                    // Don't fail here; loop and try the next method.
                    getLogger().log(Logger.ERROR, e, () ->
                            "failed to load " + method + " method");

                    methodCanceled = null;

                } catch (final SshException e) {
                    throw e;

                } catch (final Exception e) {
                    getLogger().log(Logger.ERROR, e, () -> "Authentication failure");

                    // quit the loop
                    break;
                }
            }
        }

        if (methodCanceled != null) {
            throw new SshAuthCancelException(methodCanceled);
        }

        // all methods failed 'normally'
        throw new SshAuthException("All methods failed");
    }

    @Override
    @Nullable
    public byte[] getSessionId() {
        return sessionId;
    }

    @NonNull
    @Override
    public Logger getLogger() {
        return config.getLogger();
    }

    @Override
    public void setLogger(@Nullable final Logger logger) {
        config.setLogger(logger);
    }

    @Override
    public void rekey()
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(kexDelegate, "rekey() called before 1st kex");
        kexDelegate.rekey();
    }

    private void takeKeysIntoUse(@NonNull final KexKeys keys)
            throws GeneralSecurityException, IOException {

        getLogger().log(Logger.DEBUG, () -> "SSH_MSG_NEWKEYS received");

        final byte[] K = keys.getK();
        final byte[] H = keys.getH();
        final MessageDigest md = keys.getMessageDigest();

        if (sessionId == null) {
            sessionId = new byte[H.length];
            System.arraycopy(H, 0, sessionId, 0, H.length);
        }

        /*
          Initial IV client to server:     HASH (K || H || "A" || session_id)
          Initial IV server to client:     HASH (K || H || "B" || session_id)
          Encryption key client to server: HASH (K || H || "C" || session_id)
          Encryption key server to client: HASH (K || H || "D" || session_id)
          Integrity key client to server:  HASH (K || H || "E" || session_id)
          Integrity key server to client:  HASH (K || H || "F" || session_id)
        */
        final Buffer buffer = new Buffer()
                .putMPInt(K)
                .putBytes(H);

        // The location for the 'A', 'B', ... character used
        final int cPos = buffer.writeOffset;
        buffer.putByte((byte) 'A')
              .putBytes(sessionId);
        md.update(buffer.data, 0, buffer.writeOffset);
        final byte[] iv_c2s = md.digest();

        // 'B'
        buffer.data[cPos]++;
        md.update(buffer.data, 0, buffer.writeOffset);
        final byte[] iv_s2c = md.digest();

        // 'C'
        buffer.data[cPos]++;
        md.update(buffer.data, 0, buffer.writeOffset);
        final byte[] encKey_c2s = md.digest();

        // 'D'
        buffer.data[cPos]++;
        md.update(buffer.data, 0, buffer.writeOffset);
        final byte[] encKey_s2c = md.digest();

        // 'E'
        buffer.data[cPos]++;
        md.update(buffer.data, 0, buffer.writeOffset);
        final byte[] macKey_c2s = md.digest();

        // 'F'
        buffer.data[cPos]++;
        md.update(buffer.data, 0, buffer.writeOffset);
        final byte[] macKey_s2c = md.digest();

        //noinspection ConstantConditions
        final KexAgreement agreement = kexDelegate.getAgreement();

        //noinspection ConstantConditions
        s2c.initEncryption(agreement, md, K, H, encKey_s2c, iv_s2c, macKey_s2c);
        s2c.initCompression(agreement, authenticated);

        //noinspection ConstantConditions
        c2s.initEncryption(agreement, md, K, H, encKey_c2s, iv_c2s, macKey_c2s);
        c2s.initCompression(agreement, authenticated);

        // all done, release
        kexDelegate.setKeyExchangeDone();

        if (kexDelegate.isEnforceStrictKex()) {
            getLogger().log(Logger.DEBUG, () -> "StrictKex: reset the s2c sequence number");
            s2c.resetSeq();
        }
    }

    @Override
    @NonNull
    public <T extends ChannelSession> T openChannel(@NonNull final String type)
            throws IOException, SshChannelException {
        if (!connected) {
            throw new IOException(ERROR_SESSION_IS_DOWN);
        }

        final ChannelSession channel;
        switch (type) {
            case ChannelShell.NAME:
                channel = new ChannelShellImpl(this);
                break;
            case ChannelExec.NAME:
                channel = new ChannelExecImpl(this);
                break;
            case ChannelSftp.NAME:
                channel = new ChannelSftpImpl(this);
                break;

            case ChannelSubsystem.NAME:
                channel = new ChannelSubsystemImpl(this);
                break;

            case ChannelSession.NAME:
                channel = new ChannelSessionImpl(this);
                break;

            default:
                throw new SshChannelException("Unknown channel type: " + type);
        }

        if (config.getHostConfig() != null) {
            applyHostConfig(config.getHostConfig(), channel);
        }

        //noinspection unchecked
        return (T) channel;
    }

    @Override
    @NonNull
    public Packet read()
            throws IOException, GeneralSecurityException {

        // re-used in the loop
        final Packet packet = new Packet();
        boolean done = false;
        while (!done) {
            //noinspection ConstantConditions
            s2c.read(packet);

            if (kexDelegate != null && kexDelegate.isInitialKex() && kexDelegate.isDoStrictKex()) {
                // If we're doing "strict KEX" during the initial kex-exchange
                // then we MUST ignore all packets which are not strictly required by KEX
                // So quit the while loop, and return the packet we just read immediately.
                // If it's unexpected, it will cause the connection to terminate.
                getLogger().log(Logger.DEBUG, () ->
                        "read() during initial/strict KEX: command=" + packet.getCommand());
                // quit the 'while(!done)' loop
                break;
            }

            // These need to be handled when 'read' is called from anywhere at all.
            switch (packet.getCommand()) {
                case SshConstants.SSH_MSG_DISCONNECT: {
                    packet.startReadingPayload();
                    packet.getByte(/* command */);
                    final int reasonCode = packet.getInt();
                    final String description = packet.getJString();
                    packet.skipString(/* language_tag */);
                    throw new DisconnectException(reasonCode, description);
                }
                case SshConstants.SSH_MSG_IGNORE: {
                    // loop and get the next packet
                    break;
                }
                case SshConstants.SSH_MSG_UNIMPLEMENTED: {
                    getLogger().log(Logger.DEBUG, () -> {
                        packet.startReadingPayload();
                        packet.getByte(/* command */);
                        final int packetId = packet.getInt();
                        return "SSH_MSG_UNIMPLEMENTED: " + packetId;
                    });
                    // loop and get the next packet
                    break;
                }
                case SshConstants.SSH_MSG_DEBUG: {
                    if (getLogger().isEnabled(Logger.DEBUG)) {
                        packet.startReadingPayload();
                        packet.getByte(/* command */);
                        final boolean alwaysDisplay = packet.getBoolean();
                        final String message = packet.getJString();
                        packet.skipString(/* language_tag */);

                        getLogger().log(Logger.DEBUG, "SSH_MSG_DEBUG: " + message);
                        if (alwaysDisplay && userinfo != null) {
                            userinfo.showMessage(message);
                        }
                    }
                    // loop and get the next packet
                    break;
                }
                case SshConstants.SSH_MSG_USERAUTH_SUCCESS: {
                    authenticated = true;
                    // enable delayed compression if needed
                    //noinspection ConstantConditions
                    s2c.initCompression(kexDelegate.getAgreement(), authenticated);
                    //noinspection ConstantConditions
                    c2s.initCompression(kexDelegate.getAgreement(), authenticated);

                    done = true;
                    break;
                }
                case SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST: {
                    handleChannelPacket(packet);
                    // loop and get the next packet
                    break;
                }
                default:
                    // quit the 'while(!done)' loop
                    done = true;
                    break;
            }
        }

        packet.setReadOffSet(0);
        return packet;
    }

    public boolean isInKeyExchange() {
        return kexDelegate != null && kexDelegate.isInKeyExchange();
    }

    @NonNull
    public Optional<List<String>> getServerSignatureAlgorithms() {
        if (serverSigAlgs != null && !serverSigAlgs.isEmpty()) {
            return Optional.of(serverSigAlgs);
        }
        return Optional.empty();
    }

    @NonNull
    public TransportC2S getTransportC2s() {
        return Objects.requireNonNull(c2s);
    }

    @NonNull
    public TransportS2C getTransportS2C() {
        return Objects.requireNonNull(s2c);
    }

    /**
     * Poll the {@link KexDelegate} until it either finishes the KEX, or times out.
     *
     * @throws KexTimeoutException on time out
     */
    public void waitForKexExchange()
            throws KexTimeoutException {
        final long t = timeout;

        //noinspection ConstantConditions
        while (kexDelegate.isInKeyExchange()) {
            if (kexDelegate.isTimeout(t) && !kexDelegate.isHostChecking()) {
                throw new KexTimeoutException();
            }
            try {
                Thread.sleep(10);
            } catch (final InterruptedException ignore) {
            }
        }
    }

    @Override
    public void write(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {

        final long t = timeout;
        //noinspection ConstantConditions
        while (kexDelegate.isInKeyExchange()) {
            if (kexDelegate.isTimeout(t) && !kexDelegate.isHostChecking()) {
                throw new KexTimeoutException();
            }

            // These can/must be send when we're in KeyExchange (but not timed out)
            final byte command = packet.getCommand();
            if (command == SshConstants.SSH_MSG_KEXINIT ||
                command == SshConstants.SSH_MSG_NEWKEYS ||
                command == SshConstants.SSH_MSG_DISCONNECT ||
                // 30-49	Reserved (key exchange method specific)	[RFC4251]
                (command >= 30 && command <= 49)) {
                break;
            }

            try {
                Thread.sleep(10);
            } catch (final InterruptedException ignore) {
            }
        }

        //noinspection ConstantConditions
        c2s.write(packet);

        // We could do this when we call write with the SSH_MSG_NEWKEYS.
        // But doing it here means both read/write calling .resetSeq() are
        // done from this class + it's idiot/future proof.
        if (packet.getCommand() == SshConstants.SSH_MSG_NEWKEYS
            && kexDelegate.isEnforceStrictKex()) {
            getLogger().log(Logger.DEBUG, () -> "StrictKex: reset the c2s sequence number");
            c2s.resetSeq();
        }
    }

    /**
     * The main data receiving loop.
     */
    private void run() {
        Packet packet;

        int stimeout = 0;
        try {
            while (connected && sessionThread != null) {
                final byte command;
                try {
                    packet = read();
                    command = packet.getCommand();
                    stimeout = 0;
                } catch (final InterruptedIOException /* SocketTimeoutException */ ee) {
                    //noinspection ConstantConditions
                    if (!kexDelegate.isInKeyExchange() && stimeout < serverAliveCountMax) {
                        sendKeepAlive();
                        stimeout++;
                        continue;
                    } else if (kexDelegate.isInKeyExchange() && stimeout < serverAliveCountMax) {
                        stimeout++;
                        continue;
                    }
                    throw ee;
                }

                // If the kex process is expecting another packet, redirect it.
                //noinspection ConstantConditions
                if (kexDelegate.isExpecting(command)) {
                    kexDelegate.next(packet);

                } else {
                    switch (command) {
                        case SshConstants.SSH_MSG_KEXINIT: {
                            kexDelegate.receiveKexInit(packet, authenticated);
                            break;
                        }
                        case SshConstants.SSH_MSG_NEWKEYS: {
                            final KexKeys keys = kexDelegate.sendNewKeys();
                            takeKeysIntoUse(keys);
                            break;
                        }
                        case SshConstants.SSH_MSG_EXT_INFO: {
                            if (kexDelegate != null) {
                                if (kexDelegate.isInKeyExchange()) {
                                    getLogger().log(Logger.DEBUG, () ->
                                            "SSH_MSG_EXT_INFO ignored; still in KeyExchange stage");
                                    break;
                                }
                            }

                            if (authenticated) {
                                getLogger().log(Logger.DEBUG, () ->
                                        "SSH_MSG_EXT_INFO ignored; already authenticated");
                                break;
                            }

                            handleExtInfoPacket(packet);
                            break;
                        }

                        case SshConstants.SSH_MSG_CHANNEL_REQUEST:
                        case SshConstants.SSH_MSG_CHANNEL_DATA:
                        case SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA:
                        case SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                        case SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE:
                        case SshConstants.SSH_MSG_CHANNEL_CLOSE:
                        case SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST:
                        case SshConstants.SSH_MSG_CHANNEL_EOF:
                        case SshConstants.SSH_MSG_CHANNEL_SUCCESS:
                        case SshConstants.SSH_MSG_CHANNEL_FAILURE: {
                            handleChannelPacket(packet);
                            break;
                        }
                        case SshConstants.SSH_MSG_CHANNEL_OPEN: {
                            packet.startReadingPayload();
                            packet.getByte(/* command */);
                            final String channelType = packet.getJString();
                            final boolean accept =
                                    ChannelForwardedTCPIP.NAME.equals(channelType)
                                    || ChannelX11.NAME.equals(channelType)
                                       && (x11Forwarding >= 0)
                                    || ChannelAgentForwarding.NAME.equals(channelType)
                                       && agentForwarding;

                            getLogger().log(Logger.DEBUG, () ->
                                    "Remote request to open channel: "
                                    + channelType + ", accept: " + accept);

                            if (accept) {
                                ForwardingChannel.openFromRemote(channelType, this, packet);

                            } else {
                                // use the recipient from the request?
                                final int recipient = packet.getInt();
                                sendChannelOpenFailure(recipient);
                            }
                            break;
                        }
                        case SshConstants.SSH_MSG_GLOBAL_REQUEST: {
                            // reject or ignore all global requests coming from the remote
                            packet.startReadingPayload();
                            packet.getByte(/* command */);
                            packet.skipString(/* request name */);
                            final boolean wantReply = packet.getBoolean();
                            if (wantReply) {
                                packet.init(SshConstants.SSH_MSG_REQUEST_FAILURE);
                                write(packet);
                            }
                            break;
                        }
                        case SshConstants.SSH_MSG_REQUEST_FAILURE:
                        case SshConstants.SSH_MSG_REQUEST_SUCCESS: {
                            // The only SSH_MSG_GLOBAL_REQUEST we send expecting a reply
                            // if for creating remote forwards
                            //noinspection ConstantConditions
                            remoteForwardingHandler.handleRemoteReply(packet);
                            break;
                        }
                        default: {
                            throw new IOException("Unexpected SSH message: " + command);
                        }
                    }
                }
            }
        } catch (final Exception e) {
            // paranoia
            if (kexDelegate != null) {
                kexDelegate.setKeyExchangeDone();
            }

            if (e instanceof SocketException && !connected) {
                getLogger().log(Logger.INFO, () -> "Closing Session normally");
            } else {
                getLogger().log(Logger.ERROR, e, () -> "Closing Session with error");
            }
        }

        disconnect();
    }

    /**
     * Parse the {@link SshConstants#SSH_MSG_EXT_INFO} package.
     *
     * @param packet to process
     */
    private void handleExtInfoPacket(@NonNull final Packet packet)
            throws IOException {
        getLogger().log(Logger.DEBUG, () -> "Received SSH_MSG_EXT_INFO packet");

        packet.startReadingPayload();
        packet.getByte(/* command */);
        final long nrOfExtensions = packet.getUInt();
        for (long i = 0; i < nrOfExtensions; i++) {
            final String extName = packet.getJString();
            final String extValue = packet.getJString();

            if (SshConstants.EXT_INFO_SERVER_SIG_ALGS.equals(extName)) {
                serverSigAlgs = Arrays.asList(extValue.split(","));
            }
        }
    }

    /**
     * Redirect the given packet to the channel it's meant for.
     *
     * @param packet to process
     */
    private void handleChannelPacket(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {
        packet.startReadingPayload();
        packet.getByte(); // command
        final int localChannelId = packet.getInt();

        final Channel channel = channelPool.get(localChannelId);
        if (channel != null) {
            channel.handle(packet);
        }
    }


    @Override
    public void disconnect() {
        if (!connected) {
            return;
        }

        getLogger().log(Logger.INFO, () -> "Disconnecting from " + host + ":" + port);

        // Disconnects all channels for the given session.
        // Channel disconnect will also remove from pool, so take a copy of the list first.
        final List<Channel> channelList = new ArrayList<>(channelPool.values());
        channelList.forEach(Channel::disconnect);


        //TODO: should we remove all forwards or keep them going even after the session closes?
        // need to look this up in detail in the SSH RFC
        if (localForwardingHandler != null) {
            localForwardingHandler.disconnect();
        }
        if (remoteForwardingHandler != null) {
            remoteForwardingHandler.disconnect();
        }

        connected = false;

        ChannelX11.removeAuthCookie(this);

        synchronized (this) {
            if (sessionThread != null) {
                sessionThread.interrupt();
                sessionThread = null;
            }
        }

        if (s2c != null) {
            s2c.disconnect();
        }

        if (c2s != null) {
            c2s.disconnect();
        }

        try {
            if (proxy == null) {
                if (socket != null) {
                    socket.close();
                }
            } else {
                synchronized (proxy) {
                    proxy.close();
                }
                proxy = null;
            }
        } catch (final Exception ignore) {
        }

        socket = null;

        sshClient.unregisterSession(this);
    }


    @Override
    public void setProxy(@Nullable final Proxy proxy) {
        this.proxy = proxy;
    }


    @NonNull
    public SocketFactory getSocketFactory() {
        return Objects.requireNonNull(socketFactory, "IO must be initialised first");
    }

    @Override
    public void setSocketFactory(@Nullable final SocketFactory factory) {
        socketFactory = factory;
    }

    @Override
    public boolean isConnected() {
        return connected;
    }


    @Override
    public int getTimeout() {
        return timeout;
    }

    @Override
    public void setTimeout(final int timeoutInMs)
            throws SocketException {

        this.timeout = Math.max(0, timeoutInMs);
        if (socket != null) {
            socket.setSoTimeout(timeout);
        }
    }

    @Override
    @Nullable
    public String getServerVersion() {
        return serverVersion;
    }

    @Override
    @NonNull
    public String getClientVersion() {
        return clientVersion;
    }

    @Override
    public void setClientVersion(@NonNull final String version) {
        clientVersion = version;
    }

    @Nullable
    public HostKey getHostKey() {
        return kexDelegate != null ? kexDelegate.getHostKey() : null;
    }

    @Override
    @NonNull
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    /**
     * Returns setting for the interval to send a keep-alive message.
     *
     * @see #setServerAliveInterval(int)
     */
    @SuppressWarnings({"WeakerAccess", "unused"})
    public int getServerAliveInterval() {
        return this.serverAliveInterval;
    }

    /**
     * Sets the server alive interval property.
     * This is also used as the {@link #setTimeout timeout} value (and nowhere else).
     * <p>
     * If {@code 0} is specified, no keep-alive message must be sent.
     * The default interval is {@code 0}.
     *
     * @param interval the timeout interval in milliseconds before sending
     *                 a server alive message, if no message is received from the server.
     *
     * @see #getServerAliveInterval()
     */
    @SuppressWarnings("WeakerAccess")
    public void setServerAliveInterval(final int interval)
            throws SocketException {
        setTimeout(interval);
        // set after setting setTimeout which can throw!
        this.serverAliveInterval = interval;
    }


    /**
     * Returns setting for the threshold to send keep-alive messages.
     *
     * @see #setServerAliveCountMax(int)
     */
    @SuppressWarnings({"WeakerAccess", "unused"})
    public int getServerAliveCountMax() {
        return this.serverAliveCountMax;
    }

    /**
     * Sets the number of keep-alive messages which may be sent without
     * receiving any messages back from the server.  If this threshold is
     * reached while keep-alive messages are being sent, the connection will
     * be disconnected.  The default value is one.
     *
     * @param count the specified count
     *
     * @see #getServerAliveCountMax()
     */
    @SuppressWarnings({"WeakerAccess", "unused"})
    public void setServerAliveCountMax(final int count) {
        this.serverAliveCountMax = count;
    }


    public boolean isRunningAsDaemonThread() {
        return runAsDaemonThread;
    }

    @Override
    public void setRunAsDaemon(final boolean enable) {
        runAsDaemonThread = enable;
    }


    @Override
    @NonNull
    public synchronized LocalForwardingHandler getLocalForwardingHandler() {
        if (localForwardingHandler == null) {
            localForwardingHandler = new LocalForwardingHandlerImpl(this);
        }
        return localForwardingHandler;
    }

    @Override
    @NonNull
    public RemoteForwardingHandler getRemoteForwardingHandler() {
        if (remoteForwardingHandler == null) {
            remoteForwardingHandler = new RemoteForwardingHandlerImpl(this);
        }
        return remoteForwardingHandler;
    }

    private void applyHostConfig(@NonNull final HostConfig hostConfig)
            throws IOException, GeneralSecurityException {

        String tmpValue;
        int tmpIntValue;

        tmpValue = hostConfig.getString(HostConfig.HOST_KEY_ALIAS);
        if (tmpValue != null) {
            hostKeyAlias = tmpValue;
        }

        // The server alive interval value is also set as the timeout!
        tmpIntValue = hostConfig.getIntValue(HostConfig.SERVER_ALIVE_INTERVAL, -1);
        if (tmpIntValue > -1) {
            setServerAliveInterval(tmpIntValue);
        }

        // see above, any specific timeout MUST be applied AFTER
        // the server alive interval is applied
        tmpIntValue = hostConfig.getIntValue(HostConfig.CONNECT_TIMEOUT, -1);
        if (tmpIntValue > -1) {
            setTimeout(tmpIntValue);
        }

        // Overrule the global known-hosts.
        tmpValue = hostConfig.getString(HostConfig.USER_KNOWN_HOSTS_FILE);
        if (tmpValue != null) {
            final KnownHosts kh = new KnownHosts(config);
            kh.setKnownHosts(tmpValue);
            hostKeyRepository = kh;
        }

        // Load all host specific identities (key files) into the session IdentityRepository.
        final List<String> fileNames = hostConfig.getStringList(HostConfig.IDENTITY_FILE, null);
        if (!fileNames.isEmpty()) {
            // Wrap the repo if required.
            synchronized (this) {
                final IdentityRepository repo = getIdentityRepository();
                if (!repo.supportsEncryption() && !(repo instanceof IdentityRepositoryWrapper)) {
                    this.identityRepository = new IdentityRepositoryWrapper(repo, true);
                }
            }

            // and add any non-global keys overwriting (as intended) an already present key.
            final IdentityRepository repo = this.getIdentityRepository();
            for (final String prvKeyFilename : fileNames) {
                repo.add(IdentityImpl.fromFiles(config, prvKeyFilename, null));
            }
        }
    }

    /**
     * Apply global configuration options to the given channel.
     *
     * @param channel to apply to
     */
    private void applyHostConfig(@NonNull final HostConfig hostConfig,
                                 @NonNull final ChannelSession channel) {

        Boolean enable;

        enable = hostConfig.getBooleanValue(HostConfig.FORWARD_AGENT, false);
        channel.setAgentForwarding(enable);
        if (enable) {
            agentForwarding = true;
        }

        if (channel instanceof ChannelShell) {
            final String value = hostConfig.getString(HostConfig.REQUEST_TTY);
            final boolean requestTTY =
                    ("yes".equalsIgnoreCase(value) || "true".equalsIgnoreCase(value)
                     || "force".equalsIgnoreCase(value) || "auto".equalsIgnoreCase(value));
            ((ChannelShell) channel).setPty(requestTTY);
        }

        // X11: try boolean first; if 'true' set screen number to 0
        final String value = hostConfig.getString(HostConfig.FORWARD_X11);
        enable = value != null
                 ? "yes".equalsIgnoreCase(value) || "true".equalsIgnoreCase(value)
                 : null;
        if (enable != null) {
            x11Forwarding = enable ? 0 : -1;
            channel.setXForwarding(x11Forwarding);
        } else {
            // NON-STANDARD: no boolean found, look for the int screen number
            final int nr = hostConfig.getIntValue(HostConfig.FORWARD_X11, -1);
            if (nr > -1) {
                x11Forwarding = nr;
                channel.setXForwarding(x11Forwarding);
            }
        }
    }

    @Override
    public void setAgentForwarding(final boolean enable) {
        agentForwarding = enable;
    }

    @Override
    public void setX11Forwarding(final int screenNumber) {
        x11Forwarding = screenNumber;
    }

    @Override
    public void setX11Host(@NonNull final String host) {
        ChannelX11.setHost(host);
    }

    @Override
    public void setX11Port(final int port) {
        ChannelX11.setPort(port);
    }

    @Override
    public void setX11Cookie(@NonNull final String cookie)
            throws ArrayIndexOutOfBoundsException {
        ChannelX11.setCookie(cookie);
    }

    @Override
    public void sendIgnore()
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_IGNORE);
        write(packet);
    }

    @Override
    public void sendKeepAlive()
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_GLOBAL_REQUEST)
                .putString(MSG_KEEP_ALIVE)
                .putBoolean(true);
        write(packet);
    }

    @Override
    public void sendNoMoreSessions()
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_GLOBAL_REQUEST)
                .putString("no-more-sessions@openssh.com")
                .putBoolean(false);
        write(packet);
    }

    /**
     * Sends a {@link SshConstants#SSH_MSG_CHANNEL_OPEN_FAILURE}.
     */
    private void sendChannelOpenFailure(final int recipient)
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE)
                .putInt(recipient)
                .putInt(SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
                // description; will show in the sshd logs
                .putString("")
                // language tag
                .putString("");
        write(packet);
    }

    /** Internal house-keeping. */
    public void registerChannel(@NonNull final Channel channel) {
        channelPool.put(channel.getId(), channel);
    }

    /** Internal house-keeping. */
    public void unregisterChannel(@NonNull final Channel channel) {
        channelPool.remove(channel.getId());
    }

    @Override
    public boolean equals(@Nullable final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final SessionImpl session = (SessionImpl) o;

        // If at least one has a session id, just compare the id's
        if (sessionId != null || session.sessionId != null) {
            return Arrays.equals(sessionId, session.sessionId);
        }

        // both session id's are null, compare everything
        return port == session.port
               && host.equals(session.host)
               && Objects.equals(username, session.username)
               && Arrays.equals(password, session.password)
               && Objects.equals(hostKeyAlias, session.hostKeyAlias);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(username, host, port, hostKeyAlias);
        result = 31 * result + Arrays.hashCode(sessionId);
        result = 31 * result + Arrays.hashCode(password);
        return result;
    }

}
