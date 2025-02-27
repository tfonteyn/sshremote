package com.hardbacknutter.sshclient.kex;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.userauth.SshAuthException;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.SshConstants;

public class KexProposal {

    /**
     * The lists of algorithms which we'll TRY to instantiate before declaring them to be usable.
     * This will largely depend on the device and JDK we're running on.
     * <p>
     * These checks are enabled by default, but can be disabled by setting
     * {@link ImplementationFactory#PK_VALIDATE_ALGORITHM_CLASSES} to {@code false}.
     */
    public static final String CHECK_KEX_ALGS = "class.check.kex";
    public static final String CHECK_SIG_ALGS = "class.check.signatures";
    public static final String CHECK_CIP_ALGS = "class.check.ciphers";
    public static final String CHECK_MAC_ALGS = "class.check.macs";

    /** {@link HostConfig#CIPHERS} specific for client-to-server. */
    public static final String PROPOSAL_CIPHER_CTOS = "cipher.c2s";
    /** {@link HostConfig#CIPHERS} specific for server-to-client. */
    public static final String PROPOSAL_CIPHER_STOC = "cipher.s2c";

    /** {@link HostConfig#MACS} specific for client-to-server. */
    public static final String PROPOSAL_MAC_CTOS = "mac.c2s";
    /** {@link HostConfig#MACS} specific for server-to-client. */
    public static final String PROPOSAL_MAC_STOC = "mac.s2c";

    /** {@link HostConfig#COMPRESSION} specific for client-to-server. */
    public static final String PROPOSAL_COMP_CTOS = "compression.c2s";
    /** {@link HostConfig#COMPRESSION} specific for server-to-client. */
    public static final String PROPOSAL_COMP_STOC = "compression.s2c";

    /** Language to be used for error messages; required by SSH but not actively used. */
    @SuppressWarnings("WeakerAccess")
    public static final String PROPOSAL_LANG_CTOS = "lang.c2s";
    @SuppressWarnings("WeakerAccess")
    public static final String PROPOSAL_LANG_STOC = "lang.s2c";

    /**
     * KeyExchange implementations to use.
     */
    public static final String KEY_AGREEMENT_DH = "dh";
    public static final String KEY_AGREEMENT_ECDH = "ecdh-sha2-nistp";
    public static final String KEY_AGREEMENT_XDH = "xdh";

    /** Compression type. */
    public static final String COMPRESSION_NONE = "none";
    /** Compression type. */
    public static final String COMPRESSION_ZLIB = "zlib";
    /** Compression type. */
    public static final String COMPRESSION_ZLIB_OPENSSH_COM = "zlib@openssh.com";
    /** Compression level. */
    public static final String COMPRESSION_LEVEL = "compression_level";

    @NonNull
    private final List<String> kexAlgorithms;
    @NonNull
    private final List<String> hostKeyAlgorithms;
    @NonNull
    private final List<String> ciphers_c2s;
    @NonNull
    private final List<String> ciphers_s2c;
    @NonNull
    private final List<String> mac_c2s;
    @NonNull
    private final List<String> mac_s2c;
    @NonNull
    private final List<String> compression_c2s;
    @NonNull
    private final List<String> compression_s2c;
    @NonNull
    private final List<String> language_c2s;
    @NonNull
    private final List<String> language_s2c;

    @SuppressWarnings("FieldNotUsedInToString")
    @NonNull
    private final SshClientConfig config;
    @SuppressWarnings("FieldNotUsedInToString")
    @Nullable
    private byte[] I_C;

    /**
     * Constructor.
     *
     * @throws NoSuchAlgorithmException if a deliberately configured algorithm
     *                                  is not available (i.e. we can't run without it)
     */
    public KexProposal(@NonNull final Session session,
                       @NonNull final KexProposalConfig kpc)
            throws NoSuchAlgorithmException {

        this.config = session.getConfig();

        kexAlgorithms = kpc.getKexAlgorithms();
        hostKeyAlgorithms = kpc.getHostKeyAlgorithms();

        ciphers_c2s = kpc.getCiphers_c2s();
        ciphers_s2c = kpc.getCiphers_s2c();

        mac_c2s = kpc.getMac_c2s();
        mac_s2c = kpc.getMac_s2c();

        compression_c2s = kpc.getCompression_c2s();
        compression_s2c = kpc.getCompression_s2c();

        language_c2s = kpc.getLanguage_c2s();
        language_s2c = kpc.getLanguage_s2c();
    }

    /**
     * Add a KEX extension to the list of KEX algorithms.
     * This method must be called before calling {@link #createClientPacket()}
     * to have any effect.
     *
     * @param extension to add
     */
    void addKexExtension(@NonNull final String extension) {
        if (!kexAlgorithms.contains(extension)) {
            kexAlgorithms.add(extension);
        }
    }

    /**
     * Create the client packet to use for the KEX proposal.
     *
     * @return packet to send to the server
     */
    @NonNull
    Packet createClientPacket()
            throws NoSuchAlgorithmException {
        if (I_C != null) {
            throw new IllegalStateException("Do NOT call this method twice!");
        }

        // byte      SSH_MSG_KEXINIT(20)
        // byte[16]  cookie (random bytes)
        // string    kex_algorithms
        // string    server_host_key_algorithms
        // string    encryption_algorithms_client_to_server
        // string    encryption_algorithms_server_to_client
        // string    mac_algorithms_client_to_server
        // string    mac_algorithms_server_to_client
        // string    compression_algorithms_client_to_server
        // string    compression_algorithms_server_to_client
        // string    languages_client_to_server
        // string    languages_server_to_client
        // boolean   first_kex_packet_follows
        // uint32    0 (reserved for future extension)
        final Packet packet = new Packet(SshConstants.SSH_MSG_KEXINIT)
                .putBytes(config.getRandom().nextBytes(16))
                .putString(String.join(",", kexAlgorithms))
                .putString(String.join(",", hostKeyAlgorithms))
                .putString(String.join(",", ciphers_c2s))
                .putString(String.join(",", ciphers_s2c))
                .putString(String.join(",", mac_c2s))
                .putString(String.join(",", mac_s2c))
                .putString(String.join(",", compression_c2s))
                .putString(String.join(",", compression_s2c))
                .putString(String.join(",", language_c2s))
                .putString(String.join(",", language_s2c))
                .putBoolean(false)
                .putInt(0);

        I_C = Arrays.copyOfRange(packet.data, Packet.HEADER_LEN, packet.writeOffset);
        return packet;
    }

    /**
     * Get the {@code I_C} from the previously created client-packet.
     *
     * @return I_C
     */
    @NonNull
    byte[] getIC() {
        return Objects.requireNonNull(I_C);
    }

    /**
     * The payload: (i.e. the packet without the header).
     * <p>
     * // byte      SSH_MSG_KEXINIT(20)
     * // byte[16]  cookie (random bytes)
     * <p>
     * // string    kex_algorithms
     * // string    server_host_key_algorithms
     * // string    encryption_algorithms_client_to_server
     * // string    encryption_algorithms_server_to_client
     * // string    mac_algorithms_client_to_server
     * // string    mac_algorithms_server_to_client
     * // string    compression_algorithms_client_to_server
     * // string    compression_algorithms_server_to_client
     * // string    languages_client_to_server
     * // string    languages_server_to_client
     */
    @NonNull
    KexAgreement negotiate(@NonNull final byte[] I_S,
                           final boolean authenticated)
            throws IOException, SshAuthException {
        final Buffer buffer = new Buffer(I_S);
        // 17 bytes: command(1) + cookie(16)
        buffer.setReadOffSet(17);

        final String kex = negotiate("kexAlgorithms", kexAlgorithms, buffer.getJString());
        final String key = negotiate("hostKeyAlgorithms", hostKeyAlgorithms, buffer.getJString());
        final String c_c2s = negotiate("ciphers_c2s", ciphers_c2s, buffer.getJString());
        final String c_s2c = negotiate("ciphers_s2c", ciphers_s2c, buffer.getJString());

        if (!authenticated &&
            (SshCipherConstants.NONE.equals(c_c2s) ||
             SshCipherConstants.NONE.equals(c_s2c))) {
            throw new SshAuthException("NONE Cipher cannot be chosen before auth is successful");
        }

        return new KexAgreement(
                kex, key, c_c2s, c_s2c,
                negotiate("mac_c2s", mac_c2s, buffer.getJString()),
                negotiate("mac_s2c", mac_s2c, buffer.getJString()),
                negotiate("compression_c2s", compression_c2s, buffer.getJString()),
                negotiate("compression_s2c", compression_s2c, buffer.getJString()),
                negotiate("language_c2s", language_c2s, buffer.getJString()),
                negotiate("language_s2c", language_s2c, buffer.getJString())
        );
    }

    /**
     * Try and select an option which is acceptable to both client and server.
     *
     * @param type   the type of option; this is for <strong>log/error reporting</strong> only
     * @param client what the client proposes
     * @param server what the server proposes
     *
     * @return the agreed upon value
     *
     * @throws KexNegotiationException if no agreement can be found
     */
    @NonNull
    private String negotiate(@NonNull final String type,
                             @NonNull final List<String> client,
                             @NonNull final String server)
            throws KexNegotiationException {

        final List<String> serverList = Arrays.asList(server.split(","));
        for (final String clientAlg : client) {
            if (serverList.contains(clientAlg)) {
                return clientAlg;
            }
        }
        config.getLogger().log(Logger.DEBUG, () ->
                "KEX failed negotiate: " + type
                + "|client=" + String.join(",", client)
                + "|server=" + server);

        throw new KexNegotiationException(type, server, client);
    }

    /**
     * If so configured, re-sort the algorithms, so that the ones actually
     * used by any HostKey in the repository are moved to the front of the list.
     */
    void preferKnownHostKeyTypes(@NonNull final HostKeyRepository hostKeyRepository,
                                 @NonNull final String host) {

        final List<HostKey> hks = hostKeyRepository.getHostKeys(host, null);
        if (!hks.isEmpty()) {
            final List<String> preferred = new ArrayList<>();
            final List<String> others = new ArrayList<>(hostKeyAlgorithms);

            for (final String algo : hostKeyAlgorithms) {

                final String type;
                if (HostKeyAlgorithm.isRSA(algo)) {
                    type = HostKeyAlgorithm.SSH_RSA;
                } else {
                    type = algo;
                }

                for (final HostKey hk : hks) {
                    if (type.equals(hk.getType())) {
                        preferred.add(algo);
                        others.remove(algo);
                        break;
                    }
                }
            }

            hostKeyAlgorithms.clear();
            hostKeyAlgorithms.addAll(preferred);
            hostKeyAlgorithms.addAll(others);
        }
    }

    @Override
    public String toString() {
        return "KexProposal{"
               + "kexAlgorithms=" + kexAlgorithms
               + ", hostKeyAlgorithms=" + hostKeyAlgorithms
               + ", ciphers_c2s=" + ciphers_c2s
               + ", ciphers_s2c=" + ciphers_s2c
               + ", mac_c2s=" + mac_c2s
               + ", mac_s2c=" + mac_s2c
               + ", compression_c2s=" + compression_c2s
               + ", compression_s2c=" + compression_s2c
               + ", language_c2s=" + language_c2s
               + ", language_s2c=" + language_s2c
               + '}';
    }

    /**
     * Indicates what to do if the server's host key changed or the server is unknown.
     * One of:
     * <ul>
     *     <li>{@code "yes"}: refuse connection)/li>
     *     <li>{@code "accept-new"}: automatically add new host keys, but will not permit
     *          changed host keys./li>
     *     <li>{@code "no"}:  automatically add new host keys to the user known hosts files,
     *          and allow connections to hosts with changed host-keys to proceed</li>
     *     <li>{@code "ask"}: (the default) ask the user whether to add/change the key</li>
     * </ul>
     */
    public enum StrictHostKeyChecking {
        Yes("yes"),
        No("no"),
        Ask("ask"),
        AcceptNew("accept-new");

        @NonNull
        public final String value;

        StrictHostKeyChecking(@NonNull final String value) {
            this.value = value;
        }

        @NonNull
        public static StrictHostKeyChecking get(@NonNull final SshClientConfig config) {
            return get(config.getString(HostConfig.STRICT_HOST_KEY_CHECKING));
        }

        @NonNull
        public static StrictHostKeyChecking get(@Nullable final String value) {
            if (value == null) {
                return AcceptNew;
            }
            switch (value.toLowerCase(Locale.ENGLISH)) {
                case "yes":
                    return Yes;
                case "no":
                    return No;
                case "ask":
                    return Ask;
                default:
                    return AcceptNew;
            }
        }
    }
}
