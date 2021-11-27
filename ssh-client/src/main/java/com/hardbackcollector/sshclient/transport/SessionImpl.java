/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Channel;
import com.hardbackcollector.sshclient.ChannelExec;
import com.hardbackcollector.sshclient.ChannelSession;
import com.hardbackcollector.sshclient.ChannelSftp;
import com.hardbackcollector.sshclient.ChannelShell;
import com.hardbackcollector.sshclient.ChannelSubsystem;
import com.hardbackcollector.sshclient.LocalForwardingHandler;
import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.RemoteForwardingHandler;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.SocketFactory;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.channels.forward.ChannelAgentForwarding;
import com.hardbackcollector.sshclient.channels.forward.ChannelForwardedTCPIP;
import com.hardbackcollector.sshclient.channels.forward.ChannelX11;
import com.hardbackcollector.sshclient.channels.forward.ForwardingChannel;
import com.hardbackcollector.sshclient.channels.forward.RemoteForwardingHandlerImpl;
import com.hardbackcollector.sshclient.channels.session.ChannelExecImpl;
import com.hardbackcollector.sshclient.channels.session.ChannelSessionImpl;
import com.hardbackcollector.sshclient.channels.session.ChannelShellImpl;
import com.hardbackcollector.sshclient.channels.session.ChannelSubsystemImpl;
import com.hardbackcollector.sshclient.channels.sftp.ChannelSftpImpl;
import com.hardbackcollector.sshclient.forwarding.LocalForwardingHandlerImpl;
import com.hardbackcollector.sshclient.forwarding.PortForwardException;
import com.hardbackcollector.sshclient.hostconfig.HostConfigRepository;
import com.hardbackcollector.sshclient.hostkey.HostKey;
import com.hardbackcollector.sshclient.hostkey.HostKeyRepository;
import com.hardbackcollector.sshclient.hostkey.KnownHosts;
import com.hardbackcollector.sshclient.identity.IdentityImpl;
import com.hardbackcollector.sshclient.identity.IdentityRepository;
import com.hardbackcollector.sshclient.identity.IdentityRepositoryWrapper;
import com.hardbackcollector.sshclient.kex.KexAgreement;
import com.hardbackcollector.sshclient.kex.KexDelegate;
import com.hardbackcollector.sshclient.kex.KexException;
import com.hardbackcollector.sshclient.kex.KexKeys;
import com.hardbackcollector.sshclient.kex.KexProposal;
import com.hardbackcollector.sshclient.kex.KexTimeoutException;
import com.hardbackcollector.sshclient.proxy.Proxy;
import com.hardbackcollector.sshclient.userauth.SshAuthCancelException;
import com.hardbackcollector.sshclient.userauth.SshAuthException;
import com.hardbackcollector.sshclient.userauth.SshAuthNoSuchMethodException;
import com.hardbackcollector.sshclient.userauth.SshPartialAuthException;
import com.hardbackcollector.sshclient.userauth.UserAuth;
import com.hardbackcollector.sshclient.userauth.UserAuthNone;
import com.hardbackcollector.sshclient.userauth.UserInfo;
import com.hardbackcollector.sshclient.utils.Buffer;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;
import com.hardbackcollector.sshclient.utils.SshClientConfigImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;
import com.hardbackcollector.sshclient.utils.SshException;

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
import java.util.StringJoiner;

/**
 * A Session represents a connection to a SSH server.
 * <p>
 * A session is opened with {@link #connect()} and closed with {@link #disconnect}.
 * <p>
 * One session can contain multiple {@link Channel}s of various types,
 * created with {@link #openChannel} and closed with {@link Channel#disconnect()}
 * <p>
 * The fact that a Session implements Runnable is an implementation detail.
 */
public class SessionImpl
        implements Session, PacketIO, Runnable {

    /**
     * All channels opened by this session.
     */
    private static final Map<Integer, Channel> channelPool =
            Collections.synchronizedMap(new HashMap<>());

    private static final byte[] MSG_KEEP_ALIVE = "keepalive@jcraft.com"
            .getBytes(StandardCharsets.UTF_8);

    private static final String ERROR_SESSION_IS_DOWN =
            "Session is not connected";

    @Nullable
    private final HostConfigRepository.HostConfig hostConfig;

    @NonNull
    private final SshClientConfigImpl config;
    /**
     * Used for callback when this session is disconnected.
     */
    @NonNull
    private final SshClient client;
    /**
     * Separates all logic for handling forwarding of ports and sockets.
     */
    @Nullable
    private RemoteForwardingHandlerImpl remoteForwardingHandler;
    @Nullable
    private LocalForwardingHandlerImpl localForwardingHandler;

    private int x11Forwarding;
    private boolean agentForwarding;

    private boolean runAsDaemonThread;

    /**
     * server version.
     */
    @Nullable
    private String serverVersion;

    /**
     * client version.
     */
    @NonNull
    private String clientVersion = SshClient.VERSION;

    /**
     * Unique session id, based on the hash from the KeyExchange.
     */
    @Nullable
    private byte[] sessionId;

    @Nullable
    private TransportS2C s2c;
    @Nullable
    private TransportC2S c2s;

    @Nullable
    private String username;
    @Nullable
    private byte[] password;
    @Nullable
    private UserInfo userinfo;
    @Nullable
    private String hostKeyAlias;
    @NonNull
    private String host;
    private int port;

    @Nullable
    private SocketFactory socketFactory;
    @Nullable
    private Socket socket;
    @Nullable
    private Proxy proxy;
    private int timeout;

    private boolean connected;
    private boolean authenticated;

    @Nullable
    private Thread sessionThread;
    private int serverAliveInterval;
    private int serverAliveCountMax = 1;

    @NonNull
    private IdentityRepository identityRepository;
    @NonNull
    private HostKeyRepository hostKeyRepository;
    @Nullable
    private KexDelegate kexDelegate;

    /**
     * Create a new session object.
     * Called from {@link SshClient#getSession(String, String, int)} ONLY.
     *
     * @param identityRepository the global {@link IdentityRepository}
     *                           Can be overridden by calling
     *                           {@link #setIdentityRepository(IdentityRepository)}
     * @param hostKeyRepository  the global {@link HostKeyRepository}
     *                           Can be overridden by calling
     *                           {@link #setHostKeyRepository(HostKeyRepository)}
     * @param hostConfig         (optional) configuration with host specific settings
     */
    public SessionImpl(@NonNull final SshClient sshClient,
                       @NonNull final SshClientConfigImpl config,
                       @Nullable final String username,
                       @NonNull final String host,
                       final int port,
                       @NonNull final IdentityRepository identityRepository,
                       @NonNull final HostKeyRepository hostKeyRepository,
                       @Nullable final HostConfigRepository.HostConfig hostConfig)
            throws IOException, GeneralSecurityException, SshAuthException {

        this.client = sshClient;

        this.username = username;
        this.host = host;
        this.hostKeyAlias = host;
        this.port = port;

        this.identityRepository = identityRepository;
        this.hostKeyRepository = hostKeyRepository;

        this.hostConfig = hostConfig;
        // create a child config
        this.config = new SshClientConfigImpl(config);
        if (this.hostConfig != null) {
            applyHostConfig();
        }

        if (this.port <= 0) {
            this.port = 22;
        }

        if (this.username == null) {
            try {
                this.username = System.getProperty("user.name");
            } catch (final SecurityException ignore) {
            }
            if (this.username == null) {
                throw new SshAuthException("Username not available");
            }
        }

        if (SshClient.getLogger().isEnabled(Logger.INFO)) {
            SshClient.getLogger().log(Logger.INFO, "Session created for "
                    + username + "@" + host + ":" + port);
        }
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


    /**
     * Get the current value of the UserInfo object.
     */
    @Nullable
    public UserInfo getUserInfo() {
        return userinfo;
    }

    @Override
    public void setUserInfo(@Nullable final UserInfo userinfo) {
        this.userinfo = userinfo;
    }


    /**
     * Note that the {@link Session} interface API returns {@link SshClientConfig}.
     * But here we return the implementation as this call is also used internally
     * when we need internal methods from the configuration object.
     *
     * @return config object
     */
    @Override
    @NonNull
    public SshClientConfigImpl getConfig() {
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
        return identityRepository;
    }

    @Override
    public void setIdentityRepository(@NonNull final IdentityRepository identityRepository) {
        this.identityRepository = identityRepository;
    }

    @Override
    @NonNull
    public HostKeyRepository getHostKeyRepository() {
        return hostKeyRepository;
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

        if (SshClient.getLogger().isEnabled(Logger.INFO)) {
            SshClient.getLogger().log(Logger.INFO, "Connecting to " + host + ":" + port);
        }

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

            s2c = new TransportS2C(config, socketInputStream);
            c2s = new TransportC2S(config, socketOutputStream);

            connected = true;

            // Step 1: verify the client and server support each others version
            c2s.writeVersion(clientVersion);
            serverVersion = s2c.readVersion();

            // Step 2: the full KeyExchange to agree on
            kexDelegate = new KexDelegate(this, serverVersion, clientVersion,
                    createHostKeyName());

            final KexKeys keys = kexDelegate.startExchange(hostKeyRepository, userinfo);
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
                    sessionThread = new Thread(this);
                    sessionThread.setName("Session to: " + host);
                    if (runAsDaemonThread) {
                        sessionThread.setDaemon(true);
                    }
                    sessionThread.start();

                    // add (start) the hostConfig forwards if allowed.
                    if (hostConfig != null && !config.isClearAllForwards()) {
                        initForwards();
                    }
                }
            }

            if (SshClient.getLogger().isEnabled(Logger.INFO)) {
                SshClient.getLogger().log(Logger.INFO, "Connection established");
            }

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
        Objects.requireNonNull(hostConfig);

        List<String> values;

        values = hostConfig.getLocalForwards();
        if (!values.isEmpty()) {
            // get or create the #localForwardingHandler
            final LocalForwardingHandler handler = getLocalForwardingHandler();
            for (final String connectString : values) {
                handler.add(connectString);
            }
        }

        values = hostConfig.getRemoteForwards();
        if (!values.isEmpty()) {
            // get or create the #remoteForwardingHandler
            final RemoteForwardingHandler handler = getRemoteForwardingHandler();
            for (final String connectString : values) {
                handler.add(connectString);
            }
        }
    }

    private void cleanup(final Exception e) {
        // paranoia
        if (kexDelegate != null) {
            kexDelegate.setKeyExchangeDone();
        }

        if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
            SshClient.getLogger().log(Logger.DEBUG, "KEX", e);
        }

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
                .getStringList(HostConfigRepository.HostConfig.PREFERRED_AUTHENTICATIONS);
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

                if (SshClient.getLogger().isEnabled(Logger.INFO)) {
                    final StringJoiner sj = new StringJoiner(
                            ",", "Authentications that can continue: ",
                            "; Next is: " + method);
                    for (int k = nextMethod - 1; k < clientMethods.size(); k++) {
                        sj.add(clientMethods.get(k));
                    }
                    SshClient.getLogger().log(Logger.INFO, sj.toString());
                }

                try {
                    ua = ImplementationFactory.getUserAuth(config, method);
                    ua.init(config, username, userinfo);
                    auth = ua.authenticate(this, this, password);
                    if (auth) {
                        if (SshClient.getLogger().isEnabled(Logger.INFO)) {
                            SshClient.getLogger()
                                    .log(Logger.INFO, "Authentication success: " + method);
                        }
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
                    if (SshClient.getLogger().isEnabled(Logger.WARN)) {
                        SshClient.getLogger().log(Logger.WARN,
                                "failed to load " + method + " method", e);
                    }
                    methodCanceled = null;

                } catch (final SshException e) {
                    throw e;

                } catch (final Exception e) {
                    // quit the loop
                    if (SshClient.getLogger().isEnabled(Logger.ERROR)) {
                        SshClient.getLogger().log(Logger.ERROR, "Authenticate: ", e);
                    }
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

    @Override
    public void rekey()
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(kexDelegate, "rekey() called before 1st kex").rekey();
    }

    private void takeKeysIntoUse(@NonNull final KexKeys keys)
            throws GeneralSecurityException, IOException {

        if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
            SshClient.getLogger().log(Logger.DEBUG, "SSH_MSG_NEWKEYS received");
        }

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

        if (hostConfig != null) {
            applyHostConfig(channel);
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

            // These need to be handled when 'read' is called from anywhere at all.
            switch (packet.getCommand()) {
                case SshConstants.SSH_MSG_DISCONNECT: {
                    packet.startReadingPayload();
                    packet.getByte(); // command
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
                    if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
                        packet.startReadingPayload();
                        packet.getByte(); // command
                        final int packetId = packet.getInt();

                        SshClient.getLogger()
                                .log(Logger.DEBUG, "SSH_MSG_UNIMPLEMENTED: " + packetId);
                    }
                    // loop and get the next packet
                    break;
                }
                case SshConstants.SSH_MSG_DEBUG: {
                    if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
                        packet.startReadingPayload();
                        packet.getByte(); // command
                        final boolean always_display = packet.getBoolean();
                        final String message = packet.getJString();
                        packet.skipString(/* language_tag */);

                        SshClient.getLogger().log(Logger.DEBUG, "SSH_MSG_DEBUG: " + message);
                        if (always_display && userinfo != null) {
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
    public TransportC2S getTransportC2s() {
        return Objects.requireNonNull(c2s);
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
    }

    /**
     * The main data receiving loop.
     */
    @Override
    public void run() {
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
                            packet.getByte();
                            final String channelType = packet.getJString();
                            final boolean accept =
                                    ChannelForwardedTCPIP.NAME.equals(channelType)
                                            || ChannelX11.NAME.equals(channelType)
                                            && (x11Forwarding >= 0)
                                            || ChannelAgentForwarding.NAME.equals(channelType)
                                            && agentForwarding;

                            if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
                                SshClient.getLogger().log(Logger.DEBUG,
                                        "Remote request to open channel: "
                                                + channelType + ", accept: " + accept);
                            }

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
                            packet.getByte();
                            packet.skipString(/* request name */);
                            final boolean wantReply = packet.getBoolean();
                            if (wantReply) {
                                packet.startCommand(SshConstants.SSH_MSG_REQUEST_FAILURE);
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
            if (SshClient.getLogger().isEnabled(Logger.WARN)) {
                if (e instanceof SocketException && !connected) {
                    SshClient.getLogger().log(Logger.WARN, "Closing Session normally");
                } else {
                    SshClient.getLogger().log(Logger.WARN, "Closing Session with error", e);
                }
            }
        }

        disconnect();
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

        if (SshClient.getLogger().isEnabled(Logger.INFO)) {
            SshClient.getLogger().log(Logger.INFO, "Disconnecting from " + host + ":" + port);
        }

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

        client.onSessionDisconnected(this);
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

    /**
     * retrieves the current timeout setting.
     *
     * @see #setTimeout
     */
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

    /**
     * Get the host key of the server.
     * This is only valid after a successful {@link #connect}.
     *
     * @return the HostKey used by the remote host,
     * or {@code null}, if we are not yet connected.
     */
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
    @SuppressWarnings("WeakerAccess")
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
    @SuppressWarnings("WeakerAccess")
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
     * @see #getServerAliveCountMax()
     */
    @SuppressWarnings("WeakerAccess")
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


    private void applyHostConfig()
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(hostConfig);

        String tmpValue;
        Integer tmpIntValue;

        // The user name is ONLY taken from the host-config if it was not set before
        if (username == null) {
            tmpValue = hostConfig.getUser();
            if (tmpValue != null) {
                username = tmpValue;
            }
        }

        // The passed in host name can be an alias as used above to lookup the HostConfig.
        // If the HostConfig has the real host name (or is identical) use that one.
        tmpValue = hostConfig.getHostname();
        if (tmpValue != null) {
            host = tmpValue;
        }

        tmpIntValue = hostConfig.getPort();
        if (tmpIntValue <= 0) {
            port = tmpIntValue;
        }

        tmpValue = hostConfig.getHostKeyAlias();
        if (tmpValue != null) {
            hostKeyAlias = tmpValue;
        }

        // The server alive interval value is also set as the timeout!
        tmpIntValue = hostConfig
                .getIntegerValue(HostConfigRepository.HostConfig.SERVER_ALIVE_INTERVAL);
        if (tmpIntValue != null) {
            setServerAliveInterval(tmpIntValue);
        }

        // see above, any specific timeout MUST be applied AFTER
        // the server alive interval is applied
        tmpIntValue = hostConfig.getIntegerValue(HostConfigRepository.HostConfig.CONNECT_TIMEOUT);
        if (tmpIntValue != null) {
            setTimeout(tmpIntValue);
        }

        // Overrule the global known-hosts.
        tmpValue = hostConfig.getString(HostConfigRepository.HostConfig.USER_KNOWN_HOSTS_FILE);
        if (tmpValue != null) {
            final KnownHosts kh = new KnownHosts(config);
            kh.setKnownHosts(tmpValue);
            hostKeyRepository = kh;
        }

        // Overrule the global setting.
        tmpValue = hostConfig.getPubkeyAcceptedAlgorithms();
        if (tmpValue.isBlank()) {
            config.putString(HostConfigRepository.HostConfig.PUBKEY_ACCEPTED_ALGORITHMS, tmpValue);
        }

        // Load all host specific identities (key files) into the session IdentityRepository.
        final List<String> fileNames = hostConfig.getIdentityFiles();
        if (!fileNames.isEmpty()) {
            // Wrap the repo if required.
            synchronized (this) {
                if (!identityRepository.supportsEncryption()
                        && !(identityRepository instanceof IdentityRepositoryWrapper)) {

                    identityRepository = new IdentityRepositoryWrapper(identityRepository,
                            true);
                }
            }

            // and add any non-global keys overwriting (as intended) an already present key.
            for (final String prvKeyFilename : fileNames) {
                identityRepository.add(IdentityImpl.fromFiles(config, prvKeyFilename, null));
            }
        }

        // copy/overwrite if the key is present in the hostConfig
        copyStringIfSet(KexProposal.PROPOSAL_KEX_ALGS);
        copyStringIfSet(KexProposal.PROPOSAL_HOST_KEY_ALGS);

        copyStringIfSet(KexProposal.PROPOSAL_ENC_ALGS_STOC);
        copyStringIfSet(KexProposal.PROPOSAL_ENC_ALGS_CTOS);
        copyStringIfSet(KexProposal.PROPOSAL_MAC_ALGS_CTOS);
        copyStringIfSet(KexProposal.PROPOSAL_MAC_ALGS_STOC);
        copyStringIfSet(KexProposal.PROPOSAL_COMP_ALGS_CTOS);
        copyStringIfSet(KexProposal.PROPOSAL_COMP_ALGS_STOC);

        copyStringIfSet(HostConfigRepository.HostConfig.STRICT_HOST_KEY_CHECKING);
        copyStringIfSet(HostConfigRepository.HostConfig.PREFERRED_AUTHENTICATIONS);
        copyStringIfSet(HostConfigRepository.HostConfig.NUMBER_OF_PASSWORD_PROMPTS);
        copyStringIfSet(HostConfigRepository.HostConfig.FINGERPRINT_HASH);
        copyBoolIfSet(HostConfigRepository.HostConfig.HASH_KNOWN_HOSTS);
        copyBoolIfSet(HostConfigRepository.HostConfig.CLEAR_ALL_FORWARDS);

        // Not expected to be there, but we might as well support it.
        copyBoolIfSet(KexDelegate.PREFER_KNOWN_HOST_KEY_TYPES);
        copyStringIfSet(KexProposal.COMPRESSION_LEVEL);
    }

    private void copyBoolIfSet(@NonNull final String key) {
        //noinspection ConstantConditions
        final Boolean value = this.hostConfig.getBooleanValue(key);
        if (value != null) {
            config.putString(key, String.valueOf(value));
        }
    }

    private void copyStringIfSet(@NonNull final String key) {
        //noinspection ConstantConditions
        final String value = this.hostConfig.getString(key);
        if (value != null) {
            config.putString(key, value);
        }
    }

    /**
     * Apply global configuration options to the given channel.
     *
     * @param channel to apply to
     */
    private void applyHostConfig(@NonNull final ChannelSession channel) {
        Objects.requireNonNull(hostConfig);

        Boolean enable;

        enable = hostConfig.getBooleanValue(HostConfigRepository.HostConfig.FORWARD_AGENT);
        if (enable != null) {
            channel.setAgentForwarding(enable);
            if (enable) {
                agentForwarding = true;
            }
        }

        if (channel instanceof ChannelShell) {
            enable = hostConfig.getBooleanValue(HostConfigRepository.HostConfig.REQUEST_TTY);
            if (enable != null) {
                ((ChannelShell) channel).setPty(enable);
            }
        }

        // X11: try boolean first; if 'true' set screen number to 0
        enable = hostConfig.getBooleanValue(HostConfigRepository.HostConfig.FORWARD_X11);
        if (enable != null) {
            x11Forwarding = enable ? 0 : -1;
            channel.setXForwarding(x11Forwarding);
        } else {
            // no boolean found, look for the int screen number
            final Integer nr = hostConfig.getIntegerValue(
                    HostConfigRepository.HostConfig.FORWARD_X11);
            if (nr != null) {
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

    /**
     * Sends a {@link SshConstants#SSH_MSG_IGNORE}.
     * <p>
     * Not used internally, but can called by users.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4251.html#section-9.3.1">
     * RFC 4251 Protocol Architecture, section 9.3.1. (to avoid the Rogaway attack)</a>
     */
    public void sendIgnore()
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_IGNORE);
        write(packet);
    }

    /**
     * Sends a global "keepalive" message.
     * <p>
     * This is used internally, but can also be called by users.
     */
    @SuppressWarnings("WeakerAccess")
    public void sendKeepAlive()
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_GLOBAL_REQUEST)
                .putString(MSG_KEEP_ALIVE)
                .putByte((byte) 1);
        write(packet);
    }

    /**
     * Sends a global "no-more-sessions" message.
     * <p>
     * Not used internally, but can called by users.
     *
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     * SSH protocol version 2 vendor extensions, section 2.2</a>
     */
    public void sendNoMoreSessions()
            throws IOException, GeneralSecurityException {
        final Packet packet = new Packet(SshConstants.SSH_MSG_GLOBAL_REQUEST)
                .putString("no-more-sessions@openssh.com")
                .putByte((byte) 0);
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

    public void registerChannel(@NonNull final Channel channel) {
        channelPool.put(channel.getId(), channel);
    }

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
