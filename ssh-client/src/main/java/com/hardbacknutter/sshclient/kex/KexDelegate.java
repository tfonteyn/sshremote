package com.hardbacknutter.sshclient.kex;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicBoolean;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchange;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.userauth.SshAuthException;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.SshConstants;

/**
 * Manages the interaction between the session and the physical {@link KeyExchange}.
 * <p>
 * Key exchange begins by each side sending the following packet:
 * <p>
 * byte         SSH_MSG_KEXINIT
 * byte[16]     cookie (random bytes)
 * name-list    kex_algorithms
 * name-list    server_host_key_algorithms
 * name-list    encryption_algorithms_client_to_server
 * name-list    encryption_algorithms_server_to_client
 * name-list    mac_algorithms_client_to_server
 * name-list    mac_algorithms_server_to_client
 * name-list    compression_algorithms_client_to_server
 * name-list    compression_algorithms_server_to_client
 * name-list    languages_client_to_server
 * name-list    languages_server_to_client
 * boolean      first_kex_packet_follows
 * uint32       0 (reserved for future extension)
 * <p>
 * Each of the algorithm name-lists MUST be a comma-separated list of
 * algorithm names (see Algorithm Naming in [SSH-ARCH] and additional
 * information in [SSH-NUMBERS]).  Each supported (allowed) algorithm
 * MUST be listed in order of preference, from most to least.
 * <p>
 * The first algorithm in each name-list MUST be the preferred (guessed)
 * algorithm.  Each name-list MUST contain at least one algorithm name.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-7.1">
 *         RFC 4253 SSH Transport Layer Protocol, section 7.1. Algorithm Negotiation</a>
 */
public class KexDelegate {

    /** Boolean */
    @SuppressWarnings("WeakerAccess")
    public static final String PREFER_KNOWN_HOST_KEY_TYPES = "prefer_known_host_key_types";

    /**
     * Configuration flag.
     * <p>
     * Default: {@code true}
     * <p>
     * Whether to signal the server that we support receiving the SSH2_MSG_EXT_INFO
     * message during user authentication.
     *
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     *         OpenSSH protocol deviations
     *         1.11 transport: SSH2_MSG_EXT_INFO during user authentication</a>
     */
    public static final String PK_ENABLE_EXT_INFO_IN_AUTH = "enable_ext_info_in_auth";

    /**
     * Configuration flag.
     * <p>
     * Default: {@code true}
     * <p>
     * Set to {@code false} to disable support for strict-kex functionality.
     * <strong>NOT RECOMMENDED</strong> to disable.
     *
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     *         OpenSSH protocol deviations.
     *         1.10 transport: strict key exchange extension</a>
     */
    public static final String PK_STRICT_KEX_ENABLED = "strict_kex_enabled";

    /**
     * Configuration flag.
     * <p>
     * Default: {@code false}
     * <p>
     * Set to {@code true} to <strong>require</strong> the server to support
     * strict-kex functionality.
     * <strong>RECOMMENDED</strong> but the server needs to support it.
     *
     * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
     *         OpenSSH protocol deviations.
     *         1.10 transport: strict key exchange extension</a>
     */
    public static final String PK_STRICT_KEX_REQUIRED = "strict_kex_required";

    private static final String EXT_KEX_STRICT_S_V00 = "kex-strict-s-v00@openssh.com";
    private static final String EXT_KEX_STRICT_C_V00 = "kex-strict-c-v00@openssh.com";
    /**
     * Pseudo KEX algorithm send by the server to report which extensions ir supports.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8308#section-2.1">
     *         RFC 8308</a>
     */
    private static final String EXT_INFO_S = "ext-info-s";
    /**
     * Pseudo KEX algorithm send by this client to the server
     * to report which extensions we support.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8308#section-2.1">
     *         RFC 8308</a>
     */
    private static final String EXT_INFO_C = "ext-info-c";


    /** The standard Java resource bundle with (translated) messages. */
    private static final String USER_MESSAGES = "msg.usermessages";

    @NonNull
    private final String serverVersion;
    @NonNull
    private final String clientVersion;

    @NonNull
    private final String hostKeyName;

    @NonNull
    private final SessionImpl session;

    private final AtomicBoolean inKeyExchange = new AtomicBoolean();
    private final AtomicBoolean inHostCheck = new AtomicBoolean();

    private final boolean strictKexEnabled;
    private final boolean strictKexRequired;
    /** Flag set when the server is indicating/requesting StrictKex feature support. */
    private boolean doStrictKex;

    private long inKeyExchangeStartTime;

    @Nullable
    private HostKey hostKey;

    /** The proposal this client sends to the remote server. */
    @Nullable
    private KexProposal kexProposal;
    /** The agreement between client and server on what algorithms etc. to use. */
    @Nullable
    private KexAgreement agreement;
    /** The chosen implementation for the host key exchange. */
    private KeyExchange kex;

    /** Flag set when the server reported it is supporting extensions. */
    private boolean serverSupportsExtInfo;

    /**
     * Flag which is {@code true} during the initial KEX exchange
     * but {@code false} for subsequent re-keying
     */
    private boolean initialKex = true;

    /**
     * Constructor.
     * <p>
     * The {@code hostKeyName} must be in one of the formats:
     * <ul>
     *     <li>hostKeyAlias</li>
     *     <li>hostname</li>
     *     <li>"[" + hostname + "]:" + port</li>
     * </ul>
     *
     * @param hostKeyName the hostname/alias for use in host key lookup etc..
     */
    public KexDelegate(@NonNull final SessionImpl session,
                       @NonNull final String serverVersion,
                       @NonNull final String clientVersion,
                       @NonNull final String hostKeyName)
            throws NoSuchAlgorithmException {
        this.session = session;
        this.serverVersion = serverVersion;
        this.clientVersion = clientVersion;
        this.hostKeyName = hostKeyName;

        final SshClientConfig config = session.getConfig();
        strictKexEnabled = config.getBooleanValue(PK_STRICT_KEX_ENABLED, true);
        strictKexRequired = config.getBooleanValue(PK_STRICT_KEX_REQUIRED, false);
    }

    /**
     * Check if we are actively exchanging keys.
     *
     * @return {@code true} if we are
     */
    public boolean isInKeyExchange() {
        return inKeyExchange.get();
    }

    public void setKeyExchangeDone() {
        inKeyExchange.set(false);
    }

    /**
     * Check if we are currently checking the host.
     * This may involve an interaction with the user and time spend here should NOT
     * affect the timeout.
     *
     * @return {@code true} if we are
     */
    public boolean isHostChecking() {
        return inHostCheck.get();
    }

    /**
     * (re)start the timeout timer.
     */
    private void startTimer() {
        inKeyExchangeStartTime = System.currentTimeMillis();
    }

    public boolean isTimeout(final long timeout) {
        return (timeout > 0)
               && ((System.currentTimeMillis() - inKeyExchangeStartTime) > timeout);
    }

    /**
     * Start the initial key exchange. Should be called immediately after constructor.
     *
     * @return the keys to use for the initial exchange
     */
    @NonNull
    public KexKeys startExchange(@NonNull final HostKeyRepository hostKeyRepository,
                                 @Nullable final UserInfo userinfo)
            throws IOException, GeneralSecurityException, SshAuthException {

        // Using the *current* configuration, load and check all algorithms.
        kexProposal = new KexProposal(session);
        if (session.getConfig().getBooleanValue(PREFER_KNOWN_HOST_KEY_TYPES, true)) {
            kexProposal.preferKnownHostKeyTypes(hostKeyRepository, hostKeyName);
        }
        session.getLogger().log(Logger.DEBUG, () -> "SSH_MSG_KEXINIT sent (initial request)");

        sendKexInit();

        // Read the response into the buffer
        Packet packet = session.read();
        final byte command = packet.getCommand();
        if (command != SshConstants.SSH_MSG_KEXINIT) {
            inKeyExchange.set(false);
            throw new KexProtocolException(SshConstants.SSH_MSG_KEXINIT, command);
        }

        // Setup the initial KeyExchange
        receiveKexInit(packet, false);

        do {
            // read the next KeyExchange packet received
            packet = session.read();
            final byte nextCommand = packet.getCommand();

            session.getLogger().log(Logger.DEBUG, () -> "received: " + nextCommand);

            // and if it's what the KeyExchange expected, check its validity
            if (kex.isExpecting(nextCommand)) {
                startTimer();
                try {
                    kex.next(packet);
                } catch (final GeneralSecurityException | IOException e) {
                    inKeyExchange.set(false);
                    throw e;
                }
            } else {
                inKeyExchange.set(false);
                throw new KexProtocolException(kex.getNextPacketExpected(), nextCommand);
            }
        } while (!kex.isExpecting(KeyExchange.STATE_END));

        // we got agreement, check if the host is who it says it is
        hostKey = checkHost(kex, hostKeyRepository, userinfo);

        // confirm we're ok with the connection by "Taking Keys Into Use"
        final KexKeys keys = sendNewKeys();

        // and check if the server is likewise ok with this
        packet = session.read();
        final byte confirmation = packet.getCommand();
        if (confirmation != SshConstants.SSH_MSG_NEWKEYS) {
            inKeyExchange.set(false);
            throw new KexProtocolException(SshConstants.SSH_MSG_NEWKEYS, confirmation);
        }

        if (initialKex && serverSupportsExtInfo) {
            // https://datatracker.ietf.org/doc/html/rfc8308#section-2.4
            // MUST send it as the next packet following the client's first
            // SSH_MSG_NEWKEYS message to the server.
            sendExtInfo();
        }

        initialKex = false;
        return keys;
    }

    public boolean isInitialKex() {
        return initialKex;
    }

    public boolean isDoStrictKex() {
        return doStrictKex;
    }

    /**
     * Check if the transport layer should enforce the "StrictKex" feature.
     * i.e. if it should reset the packet sequence numbers after sending
     * or receiving a SSH2_MSG_NEWKEYS message.
     *
     * @return flag
     */
    public boolean isEnforceStrictKex() {
        return doStrictKex && (strictKexEnabled || strictKexRequired);
    }

    private void sendExtInfo()
            throws IOException, GeneralSecurityException {
        // If we support multiple extensions, this check (and similar checks)
        // must obviously be done on a per-line basis
        if (session.getConfig().getBooleanValue(PK_ENABLE_EXT_INFO_IN_AUTH, true)) {
            session.getLogger().log(Logger.DEBUG, () -> "sending SSH_MSG_EXT_INFO");

            final Packet packet = new Packet(SshConstants.SSH_MSG_EXT_INFO)
                    .putInt(1)
                    .putString("ext-info-in-auth@openssh.com").putString("0");
            session.write(packet);
        }
    }

    /**
     * Send the pre-prepared SSH_MSG_KEXINIT to the server.
     */
    private void sendKexInit()
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(kexProposal);

        if (initialKex) {
            //URGENT: send ext-info support string
//            // Tell the server we MAY support (some) extensions
//            kexProposal.addKexExtension(EXT_INFO_C);

            // Tell the server we support the StrictKex feature.
            if (strictKexEnabled || strictKexRequired) {
                kexProposal.addKexExtension(EXT_KEX_STRICT_C_V00);
            }
        }

        inKeyExchange.set(true);
        startTimer();
        session.write(kexProposal.createClientPacket());
    }

    /**
     * Requests the server to perform a new key exchange for the session using
     * any update key exchange proposals set in the session's configuration.
     */
    public void rekey()
            throws IOException, GeneralSecurityException {
        if (!inKeyExchange.get()) {
            session.getLogger().log(Logger.DEBUG, () ->
                    "SSH_MSG_KEXINIT sent (client rekey request)");

            sendKexInit();
        }
    }

    /**
     * Receives and interprets a {@link SshConstants#SSH_MSG_KEXINIT} packet from the server.
     * <p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-7.2">
     *         RFC 4253 SSH Transport Layer Protocol, section 7.2.</a>
     */
    public void receiveKexInit(@NonNull final Packet serverPacket,
                               final boolean authenticated)
            throws IOException, GeneralSecurityException, SshAuthException {
        Objects.requireNonNull(kexProposal);

        session.getLogger().log(Logger.DEBUG, () -> "SSH_MSG_KEXINIT received");

        // The server's SSH_MSG_KEXINIT payload.
        // During the initial exchange, it's always uncompressed of course.
        // But in any subsequent exchange we CAN have compression active.
        final byte[] I_S;
        serverPacket.setReadOffSet(0);
        final int packetLength = serverPacket.getInt();
        if (packetLength == serverPacket.availableToRead()) {
            // packet was NOT compressed,
            I_S = new byte[packetLength - serverPacket.getPaddingLength() - 1];
            System.arraycopy(serverPacket.data,
                             Packet.HEADER_LEN,
                             I_S, 0, I_S.length);

        } else {
            // packet was compressed and 'packetLength' is the size of deflated packet.
            // Hence, we skip the padding byte, and use the raw content length.
            I_S = Arrays.copyOfRange(serverPacket.data,
                                     Packet.HEADER_LEN,
                                     serverPacket.writeOffset);
        }

        // Check for extension support
        final Buffer buffer = new Buffer(I_S);
        // 17 bytes: command(1) + cookie(16)
        buffer.setReadOffSet(17);
        final List<String> serverKexAlgorithms = Arrays.asList(buffer.getJString().split(","));
        serverSupportsExtInfo = serverKexAlgorithms.contains(EXT_INFO_S);

        if (initialKex) {
            // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD
            // section 1.10 transport: strict key exchange extension
            if (strictKexEnabled || strictKexRequired) {
                // Check if the server supports the "strict KEX" feature,
                doStrictKex = serverKexAlgorithms.contains(EXT_KEX_STRICT_S_V00);
                if (doStrictKex) {
                    session.getLogger().log(Logger.DEBUG, () -> "StrictKex from server");
                    // Terminate the connection if the first
                    // packet received is not SSH2_MSG_KEXINIT.
                    if (session.getTransportS2C().getSeq() != 1) {
                        throw new KexStrictViolationException(
                                "SSH_MSG_KEXINIT not first packet from server");
                    }
                } else if (strictKexRequired) {
                    throw new KexStrictViolationException(
                            "StrictKex required, but not supported by server");
                }
            }
        }

        if (!inKeyExchange.get()) {
            session.getLogger().log(Logger.DEBUG, () ->
                    "SSH_MSG_KEXINIT sent (re-keying requested by the remote)");
            sendKexInit();
        }

        agreement = kexProposal.negotiate(I_S, authenticated);

        kex = ImplementationFactory.getKeyExchange(session.getConfig(),
                                                   agreement.getKeyAlgorithm());
        kex.init(session.getConfig(),
                /* PacketIO */ session,
                 serverVersion.getBytes(StandardCharsets.UTF_8),
                 clientVersion.getBytes(StandardCharsets.UTF_8),
                 I_S,
                 kexProposal.getIC());
    }

    @NonNull
    public KexAgreement getAgreement() {
        return Objects.requireNonNull(agreement);
    }

    public boolean isExpecting(final byte command) {
        return kex != null && kex.isExpecting(command);
    }

    public void next(@NonNull final Packet packet)
            throws GeneralSecurityException, IOException {

        startTimer();
        try {
            kex.next(packet);
        } catch (final GeneralSecurityException | IOException e) {
            setKeyExchangeDone();
            throw e;
        }
    }

    /**
     * Taking Keys Into Use
     * <p>
     * Key exchange ends by each side sending an SSH_MSG_NEWKEYS message.
     * This message is sent with the old keys and algorithms.  All messages
     * sent after this message MUST use the new keys and algorithms.
     * <p>
     * When this message is received, the new keys and algorithms MUST be
     * used for receiving.
     * <p>
     * The purpose of this message is to ensure that a party is able to
     * respond with an SSH_MSG_DISCONNECT message that the other party can
     * understand if something goes wrong with the key exchange.
     * <p>
     * byte      SSH_MSG_NEWKEYS
     *
     * @return the new keys to use from now on.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-7.3">
     *         RFC 4253 SSH Transport Layer Protocol, section 7.3. Taking Keys Into Use</a>
     */
    @NonNull
    public KexKeys sendNewKeys()
            throws IOException, GeneralSecurityException {
        session.write(new Packet(SshConstants.SSH_MSG_NEWKEYS));

        session.getLogger().log(Logger.DEBUG, () -> "SSH_MSG_NEWKEYS sent");

        return new KexKeys(kex.getK(), kex.getH(), kex.getMessageDigest());
    }

    @NonNull
    private HostKey checkHost(@NonNull final KeyExchange kex,
                              @NonNull final HostKeyRepository hkr,
                              @Nullable final UserInfo userinfo)
            throws GeneralSecurityException {

        final long startTimeOfCheck = System.currentTimeMillis();
        inHostCheck.set(true);

        try {
            final KexProposal.StrictHostKeyChecking strictHostKeyChecking =
                    KexProposal.StrictHostKeyChecking.get(session.getConfig());

            final HostKey hostkey = hkr.createHostKey(hostKeyName, kex.getK_S());

            boolean addNewKey = false;

            final HostKeyRepository.KeyIs keyIs;
            synchronized (hkr) {
                keyIs = hkr.isKnown(hostKeyName, kex.getHostKeyAlgorithm(), kex.getK_S());
            }
            switch (keyIs) {
                case Accepted:
                    break;
                case Unknown: {
                    switch (strictHostKeyChecking) {
                        case Yes:
                            if (userinfo != null) {
                                userinfo.showMessage(getKeyIsUnknownMessage(kex, false));
                            }
                            throw new InvalidKeyException("Rejecting unknown key for: "
                                                          + hostKeyName);

                        case AcceptNew:
                        case No:
                            // just trust the unknown key without any checks (BAD IDEA!)
                            addNewKey = true;
                            break;

                        case Ask:
                            if (userinfo != null) {
                                addNewKey = userinfo.promptYesNo(
                                        UserInfo.RC_ACCEPT_NON_MATCHING_KEY,
                                        getKeyIsUnknownMessage(kex, true));
                                if (!addNewKey) {
                                    throw new InvalidKeyException("User rejected key for: "
                                                                  + hostKeyName);
                                }
                            } else {
                                // can't ask
                                throw new InvalidKeyException("Rejecting unknown key for: "
                                                              + hostKeyName);
                            }
                            break;
                    }

                    break;
                }
                case Changed: {
                    switch (strictHostKeyChecking) {
                        case AcceptNew:
                        case Yes: {
                            if (userinfo != null) {
                                userinfo.showMessage(getKeyIsChangedMessage(kex, false));
                            }
                            throw new InvalidKeyException(
                                    "Rejecting changed key for: " + hostKeyName);
                        }
                        case No: {
                            // Remove the old key and add the replacement without any further checks
                            addNewKey = true;
                            break;
                        }
                        case Ask: {
                            if (userinfo != null) {
                                addNewKey = userinfo.promptYesNo(
                                        UserInfo.RC_REPLACE_KEY,
                                        getKeyIsChangedMessage(kex, true));
                                if (!addNewKey) {
                                    throw new InvalidKeyException("User rejected key for: "
                                                                  + hostKeyName);
                                }
                            } else {
                                // can't ask
                                throw new InvalidKeyException("Rejecting changed key for: "
                                                              + hostKeyName);
                            }
                            break;
                        }
                    }
                    synchronized (hkr) {
                        hkr.remove(hostKeyName, kex.getHostKeyAlgorithm(), null);
                    }

                    break;
                }
                case Revoked: {
                    if (userinfo != null) {
                        final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
                        userinfo.showMessage(String.format(rb.getString("WARNING_KEY_REVOKED"),
                                                           kex.getHostKeyAlgorithm(),
                                                           hostKeyName));
                    }
                    throw new InvalidKeyException("Key was revoked: " + hostKeyName);
                }
                default:
                    // sanity check
                    throw new IllegalStateException("check=" + keyIs);
            }

            if (addNewKey) {
                session.getLogger().log(Logger.WARN, () ->
                        "Permanently added '" + hostKeyName + "'"
                        + " (" + kex.getHostKeyAlgorithm() + ")"
                        + " to the list of known hosts.");

                synchronized (hkr) {
                    hkr.add(hostkey, userinfo);
                }
            }

            inKeyExchangeStartTime = inKeyExchangeStartTime - startTimeOfCheck
                                     + System.currentTimeMillis();

            return hostkey;

        } catch (final GeneralSecurityException e) {
            inKeyExchange.set(false);
            throw e;

        } finally {
            inHostCheck.set(false);
        }
    }

    /**
     * After a successful connect, the accepted host key is available for informative purposes.
     *
     * @return the HostKey used by the remote host, or {@code null},
     *         if we are not yet connected.
     */
    @Nullable
    public HostKey getHostKey() {
        return hostKey;
    }

    @NonNull
    private String getKeyIsChangedMessage(@NonNull final KeyExchange kex,
                                          final boolean askToReplace)
            throws NoSuchAlgorithmException {

        final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
        String message = String.format(
                rb.getString("WARNING_KEY_CHANGED"),
                kex.getHostKeyAlgorithm(),
                kex.getHostKeyAlgorithm(),
                hostKeyName,
                HostKey.getFingerPrint(session.getConfig(), kex.getK_S()));
        if (askToReplace) {
            message += '\n' + rb.getString("QUESTION_REPLACE_KEY");
        }

        return message;
    }

    @NonNull
    private String getKeyIsUnknownMessage(@NonNull final KeyExchange kex,
                                          final boolean askToAdd)
            throws NoSuchAlgorithmException {

        final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
        String message = String.format(
                rb.getString("WARNING_KEY_UNKNOWN"),
                hostKeyName,
                kex.getHostKeyAlgorithm(),
                HostKey.getFingerPrint(session.getConfig(), kex.getK_S()));
        if (askToAdd) {
            message += '\n' + rb.getString("QUESTION_ADD_KEY");
        }

        return message;
    }
}
