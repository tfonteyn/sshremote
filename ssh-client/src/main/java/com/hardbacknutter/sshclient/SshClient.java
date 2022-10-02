package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfigRepository;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.hostkey.KnownHosts;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityImpl;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.identity.IdentityRepositoryWrapper;
import com.hardbacknutter.sshclient.identity.InMemoryIdentityRepository;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.userauth.SshAuthException;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.SshClientConfigImpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * This class is the central entry/configuration point.
 * It serves as a factory for {@link Session} objects which in turn can provide a {@code Channel}.
 * <ul>
 *      <li>Set any global options using {@link #setConfig}</li>
 *      <li>Instantiate a class object</li>
 *      <li>If using public-key authentication, call one of the {@link #addIdentity}
 *          methods for adding your key(s).</li>
 *      <li>Use {@link #setKnownHosts setKnownHosts} to enable
 *          checking of host keys using a "known_hosts" file</li>
 *      <li>Use {@link #getSession} to start a new {@code Session}.</li>
 * </ul>
 * <p>
 * <strong>Note that thread-safety is aimed for, but not guaranteed.</strong>
 */
public class SshClient {

    /** The standard Java resource bundle with (translated) messages. */
    public static final String USER_MESSAGES = "msg.usermessages";

    /**
     * client version: {code SSH-protoversion-softwareversion SP comments CR LF}
     * The CR+LF is added when the version is send to the server.
     * <ul>
     * <li>protoversion is always "2.0"</li>
     * <li>softwareversion MUST consist of
     *     printable US-ASCII characters, with the exception of whitespace
     *     characters and the minus sign (-)</li>
     * </ul>
     *
     * @see Session#setClientVersion(String)
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-4.2">
     * RFC 4253, section4.2</a>
     */
    public static final String VERSION = "SSH-2.0-JSCH_2.0";

    /**
     * Boolean:
     * If {@link true}, BC is used for all operations;
     * If {@link false}, the JDK has priority and BC handles only what the JDK cannot.
     */
    private static final String PREFER_BOUNCY_CASTLE = "prefer_bouncycastle";

    /**
     * A pool of all sessions currently active for this instance.
     * A {@link Session} is added when it's created, and removed upon {@link Session#disconnect()}.
     * <p>
     * Not actually used/checked for now, but it provides a way to track any sessions still open.
     * TODO: maybe add a 'disconnect' to the client ?
     */
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    private final Set<Session> sessionPool = new HashSet<>();

    /** The configuration for this client. */
    @NonNull
    private final SshClientConfig config;

    /** Public key authentication. */
    @NonNull
    private final IdentityRepository defaultIdentityRepository;

    /** Random generator used by this client. */
    @Nullable
    private Random random;

    /** Public key authentication. */
    @NonNull
    private IdentityRepository identityRepository;

    /** A repository with custom sets of configuration details for specific hosts. */
    @Nullable
    private HostConfigRepository hostConfigRepository;

    /** HostKey verification. */
    @Nullable
    private HostKeyRepository hostKeyRepository;

    private boolean globalIdentitiesLoaded;

    /**
     * Constructor.
     * <p>
     * The entry point for user-code.
     */
    public SshClient() {
        this(null);
    }

    /**
     * Constructor.
     * <p>
     * The entry point for user-code.
     *
     * @param logger to use; can be {@code null} for no logging at all.
     */
    public SshClient(@Nullable final Logger logger) {
        config = SshClientConfigImpl.createClientConfig(logger);
        defaultIdentityRepository = new InMemoryIdentityRepository(config);
        identityRepository = defaultIdentityRepository;

        try {
            // Insert the BC provider as most-preferred.
            // As some of our code relies on the objects being BC.
            // If not done, and running on Java 11+ ... the default provider(s) step in.
            // on Android, it does not actually matter of course.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            final int pos;
            if (config.getBooleanValue(PREFER_BOUNCY_CASTLE, false)) {
                pos = Security.insertProviderAt(new BouncyCastleProvider(), 1);
            } else {
                pos = Security.addProvider(new BouncyCastleProvider());
            }

            if (pos == -1) {
                if (config.getLogger().isEnabled(Logger.DEBUG)) {
                    config.getLogger().log(Logger.DEBUG, () ->
                            "BouncyCastleProvider already installed");
                }
            }
        } catch (final SecurityException e) {
            if (config.getLogger().isEnabled(Logger.FATAL)) {
                config.getLogger().log(Logger.FATAL, e, () ->
                        "BouncyCastleProvider failed to install");
            }
        }
    }

    /**
     * returns the current client {@link Logger}.
     *
     * @return the current logger
     */
    @NonNull
    public Logger getLogger() {
        return config.getLogger();
    }

    /**
     * Sets the {@link Logger} to be used by this client.
     * Existing sessions will keep using the logger as set when they where created.
     *
     * @param logger the new logger. If {@code null}, we use a builtin
     *               Logger which logs nothing.
     *
     * @see Session#setLogger(Logger)
     */
    public void setLogger(@Nullable final Logger logger) {
        config.setLogger(logger);
    }

    /**
     * Set a configuration {@link String} option.
     *
     * @param key   the key for the configuration option
     * @param value to set
     *
     * @see Session#setConfig(String, String)
     * @see SshClientConfig#putString(String, String)
     */
    public void setConfig(@NonNull final String key,
                          @NonNull final String value) {
        config.putString(key, value);
    }

    @NonNull
    public SshClientConfig getConfig() {
        return config;
    }

    /**
     * Sets multiple default configuration options at once.
     * The given hashtable should only contain Strings. Values are copied.
     *
     * @see #setConfig(String, String)
     */
    public void setConfig(@NonNull final Map<String, String> newConf) {
        synchronized (config) {
            for (final Map.Entry<String, String> entry : newConf.entrySet()) {
                config.putString(entry.getKey(), entry.getValue());
            }
        }
    }

    /**
     * Retrieves a configuration option.
     *
     * @param key key for the configuration.
     *
     * @return config value
     *
     * @see #setConfig(String, String)
     */
    @Nullable
    public String getConfig(@NonNull final String key) {
        synchronized (config) {
            return config.getString(key);
        }
    }

    @SuppressWarnings("WeakerAccess")
    @Nullable
    public HostConfigRepository getHostConfigRepository() {
        return hostConfigRepository;
    }

    @SuppressWarnings("WeakerAccess")
    public void setHostConfigRepository(@Nullable final HostConfigRepository configRepository) {
        this.hostConfigRepository = configRepository;
    }

    /**
     * Returns the current {@link HostKeyRepository}.
     * <p>
     * If not yet set by one of the methods {@link #setKnownHosts(InputStream)},
     * {@link #setKnownHosts(String)} or {@link #setHostKeyRepository},
     * this creates a new (empty) repository of type {@link KnownHosts}.
     *
     * @return current host key repository
     *
     * @see HostKeyRepository
     * @see KnownHosts
     */
    @SuppressWarnings("WeakerAccess")
    @NonNull
    public HostKeyRepository getHostKeyRepository() {
        if (hostKeyRepository == null) {
            hostKeyRepository = new KnownHosts(config);
        }
        return hostKeyRepository;
    }

    /**
     * Sets a generic/custom {@link HostKeyRepository}.
     * This will be used by sessions {@linkplain Session#connect connected}
     * in the future to validate the host keys offered by the remote hosts.
     *
     * @see HostKeyRepository
     * @see KnownHosts
     */
    public void setHostKeyRepository(@Nullable final HostKeyRepository repository) {
        hostKeyRepository = repository;
    }


    /**
     * Creates a {@link HostKeyRepository} from a file name.
     * This method uses the same format as OpenSSH's {@code known_hosts} file.
     * <p>
     * This has no effect if {@link #setHostKeyRepository} was already
     * called with an object which is not of class {@link KnownHosts}.
     *
     * @param filename the name of the file to be loaded.
     *
     * @see KnownHosts
     * @see HostKeyRepository
     * @see #setHostKeyRepository(HostKeyRepository)
     */
    @SuppressWarnings("OverlyBroadThrowsClause")
    public void setKnownHosts(@NonNull final String filename)
            throws IOException, GeneralSecurityException {
        if (hostKeyRepository == null) {
            hostKeyRepository = new KnownHosts(config);
        }
        if (hostKeyRepository instanceof KnownHosts) {
            synchronized (hostKeyRepository) {
                ((KnownHosts) hostKeyRepository).setKnownHosts(filename);
            }
        }
    }

    /**
     * Creates a {@link HostKeyRepository} from an InputStream.
     * This method uses the same format as OpenSSH's {@code known_hosts} file.
     * <p>
     * This has no effect if {@link #setHostKeyRepository} was already
     * called with an object which is not of class {@link KnownHosts}.
     *
     * @param stream an InputStream with the list of known hosts.
     *
     * @see KnownHosts
     * @see HostKeyRepository
     * @see #setHostKeyRepository(HostKeyRepository)
     */
    @SuppressWarnings("OverlyBroadThrowsClause")
    public void setKnownHosts(@NonNull final InputStream stream)
            throws IOException, GeneralSecurityException {
        if (hostKeyRepository == null) {
            hostKeyRepository = new KnownHosts(config);
        }
        if (hostKeyRepository instanceof KnownHosts) {
            synchronized (hostKeyRepository) {
                ((KnownHosts) hostKeyRepository).setKnownHosts(stream);
            }
        }
    }


    /**
     * Instantiates a {@code Session} with the given {@code host}.
     * <p>
     * See {@link #getSession(String, String, int, String)} for full docs.
     *
     * @param host hostname
     *
     * @return a new instance of {@code Session}.
     *
     * @throws SshAuthException if {@code username} or {@code host} are invalid.
     * @see #getSession(String username, String host, int port, String hostNameOrAlias)
     */
    @NonNull
    public Session getSession(@NonNull final String host)
            throws IOException, GeneralSecurityException, SshAuthException {
        return getSession(null, host, 0, null);
    }

    /**
     * Instantiates a {@code Session} with the given {@code host} and optional {@code username}.
     * <p>
     * See {@link #getSession(String, String, int, String)} for full docs.
     *
     * @param username user name
     * @param host     hostname
     *
     * @return a new instance of {@code Session}.
     *
     * @throws SshAuthException if {@code username} or {@code host} are invalid.
     * @see #getSession(String username, String host, int port, String hostNameOrAlias)
     */
    @NonNull
    public Session getSession(@Nullable final String username,
                              @NonNull final String host)
            throws SshAuthException, IOException, GeneralSecurityException {
        return getSession(username, host, 0, null);
    }

    /**
     * Instantiates a {@code Session} with the given {@code host}, {@code port}
     * and optional {@code username}.
     * <p>
     * See {@link #getSession(String, String, int, String)} for full docs.
     *
     * @param username user name
     * @param host     hostname
     * @param port     port number
     *
     * @return a new instance of {@code Session}.
     *
     * @throws SshAuthException if {@code username} or {@code host} are invalid.
     * @see #getSession(String username, String host, int port, String hostNameOrAlias)
     */
    @NonNull
    public Session getSession(@Nullable final String username,
                              @NonNull final String host,
                              final int port)
            throws SshAuthException, IOException, GeneralSecurityException {
        return getSession(username, host, port, null);
    }

    /**
     * Instantiates a {@code Session}.
     * <p>
     * A {@code host} MUST be passed in.
     * <p>
     * If the given {@code username} is {@code null} it will be retrieved
     * from the (optional) {@link HostConfigRepository}.
     * If there is no repository, or if a user name is not present,
     * the value of the system property {@code "user.name"} will be used.
     * <p>
     * If the given {@code port} is {@code 0} (or negative) it will be retrieved
     * from the (optional) {@link HostConfigRepository}.
     * If there is no repository, or if a port value is not present,
     * the default {@code 22} is used.
     * <p>
     * The optional {@code hostKeyAlias} is used for public-key authentication.
     * If not set, the {@code host} will be used.
     * <p>
     * IMPORTANT: for all other settings, if a {@link HostConfigRepository}
     * was set, it overrides any other manual settings (e.g. timeout, algorithms etc...)
     * The exception is the {@code username} where the manually set name has precedence.
     * <p>
     * Note that the TCP connection is not established
     * until {@link Session#connect()} is called.
     *
     * @param username        user name
     * @param host            hostname
     * @param port            port number
     * @param hostNameOrAlias (optional) alias for looking a
     *                        {@link HostConfig} for the given host.
     *                        If not set, the {@code host} will be used.
     *
     * @return a new instance of {@code Session}.
     *
     * @throws SshAuthException if {@code username} or {@code host} are invalid.
     * @see HostConfigRepository
     */
    @NonNull
    public Session getSession(@Nullable final String username,
                              @NonNull final String host,
                              final int port,
                              @Nullable final String hostNameOrAlias)
            throws IOException, GeneralSecurityException, SshAuthException {

        // extra/specific config for the specified host
        final HostConfig hostConfig;
        //TODO: should we just use getHostKeyRepository()? (and never have a null hostConfig)
        if (hostConfigRepository != null) {
            initGlobalIdentities();
            hostConfig = hostConfigRepository
                    .getHostConfig(hostNameOrAlias != null ? hostNameOrAlias : host);
        } else {
            hostConfig = null;
        }

        final Session session = SessionImpl.createSession(this, hostConfig, username, host, port);

        // Not strictly needed to set the Identity and Host repos here, but it's cleaner.
        // set the global {@link IdentityRepository} for public key authentication
        session.setIdentityRepository(identityRepository);
        // set the global {@link HostKeyRepository} for host key verification
        session.setHostKeyRepository(getHostKeyRepository());

        synchronized (sessionPool) {
            sessionPool.add(session);
        }
        return session;
    }

    /**
     * Load all global identities (key files) into our IdentityRepository
     * if not already done so.
     */
    private void initGlobalIdentities()
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(hostConfigRepository);
        synchronized (this) {
            if (!globalIdentitiesLoaded) {
                final List<String> fileNames = hostConfigRepository
                        .getHostConfig("")
                        .getStringList(HostConfig.IDENTITY_FILE, null);

                for (final String prvKeyFilename : fileNames) {
                    addIdentity(prvKeyFilename, null, null);
                }

                globalIdentitiesLoaded = true;
            }
        }
    }

    @NonNull
    public synchronized IdentityRepository getIdentityRepository() {
        return identityRepository;
    }

    /**
     * Sets the {@code identityRepository}, which will be referred
     * in the public key authentication.
     *
     * @param identityRepository if {@code null} is given, the default repository,
     *                           which usually refers to ~/.ssh/, will be used.
     *
     * @see #getIdentityRepository()
     */
    public synchronized void setIdentityRepository(
            @Nullable final IdentityRepository identityRepository) {
        this.identityRepository = Objects
                .requireNonNullElse(identityRepository, defaultIdentityRepository);
    }

    /**
     * Adds an identity to be used for public-key authentication.
     *
     * @param prvKeyFilename the file name of the private key file.
     *                       This is also used as the identifying name of the key.
     *                       The corresponding public key is assumed to be in a file
     *                       with the same name with suffix {@code .pub}.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     */
    public boolean addIdentity(@NonNull final String prvKeyFilename)
            throws IOException, GeneralSecurityException {
        final Identity identity = IdentityImpl.fromFiles(config, prvKeyFilename, null);
        return addIdentity(identity, null);
    }

    /**
     * Adds a file-based identity to be used for public-key authentication.
     * <p>
     * If a passphrase is provided, decryption wil be attempted
     * before registering it into identityRepository, and if failing this method will throw.
     *
     * @param prvKeyFilename the file name of the private key file.
     *                       This is also used as the identifying name of the key.
     * @param pubKeyFilename the file name of the public key file.
     * @param passphrase     the passphrase necessary to access the private key.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     *
     * @throws InvalidKeyException if a {@code passphrase} was given, but decryption failed
     */
    @SuppressWarnings("WeakerAccess")
    public boolean addIdentity(@NonNull final String prvKeyFilename,
                               @Nullable final String pubKeyFilename,
                               @Nullable final byte[] passphrase)
            throws IOException, GeneralSecurityException {
        final Identity identity = IdentityImpl.fromFiles(config, prvKeyFilename, pubKeyFilename);
        return addIdentity(identity, passphrase);
    }

    /**
     * Adds a file-based identity to be used for public-key authentication.
     * <p>
     * If a passphrase is provided, decryption wil be attempted
     * before registering it into identityRepository, and if failing this method will throw.
     *
     * @param name       a name identifying the key pair.
     * @param prvKey     the private key data. This will be zeroed
     *                   out after creating the Identity object.
     * @param pubKey     the public key data.
     * @param passphrase the passphrase necessary to access the private key.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     *
     * @throws InvalidKeyException if a {@code passphrase} was given, but decryption failed
     */
    @SuppressWarnings({"WeakerAccess", "unused"})
    public boolean addIdentity(@NonNull final String name,
                               @NonNull final byte[] prvKey,
                               @Nullable final byte[] pubKey,
                               @Nullable final byte[] passphrase)
            throws IOException, GeneralSecurityException {
        final Identity identity = IdentityImpl.fromKeyData(config, name, prvKey, pubKey);
        return addIdentity(identity, passphrase);
    }

    /**
     * Adds a generic identity to be used for public-key authentication.
     * <p>
     * If a passphrase is provided, decryption wil be attempted
     * before registering it into identityRepository, and if failing this method will throw.
     *
     * @param identity   the Identity object encapsulating the key pair
     *                   and algorithm (or a hardware device containing them).
     * @param passphrase the passphrase necessary to access the private key.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     *
     * @throws InvalidKeyException if a {@code passphrase} was given, but decryption failed
     */
    public boolean addIdentity(@NonNull final Identity identity,
                               @Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {

        // Try to decrypt.
        if (passphrase != null) {
            final byte[] tmp = Arrays.copyOf(passphrase, passphrase.length);
            try {
                if (!identity.decrypt(tmp)) {
                    // FAIL if a passphrase was given but was incorrect
                    throw new InvalidKeyException("Decryption failed");
                }
            } finally {
                Arrays.fill(tmp, (byte) 0);
            }
        }

        // At this point the identity is successfully decrypted,
        // OR no passphrase was given and it can (potentially) still be encrypted.

        // Wrap the repo if required.
        synchronized (identityRepository) {
            if (identity.isEncrypted()
                    && !identityRepository.supportsEncryption()
                    && !(identityRepository instanceof IdentityRepositoryWrapper)) {

                identityRepository = new IdentityRepositoryWrapper(identityRepository,
                                                                   false);
            }
        }

        return identityRepository.add(identity);
    }

    /**
     * INTERNAL USE ONLY.
     */
    @NonNull
    public Random getRandom()
            throws NoSuchAlgorithmException {
        synchronized (this) {
            if (random == null) {
                random = ImplementationFactory.getRandom(config);
            }
        }
        return random;
    }

    /**
     * INTERNAL USE ONLY.
     * <p>
     * Removes a session from our session pool.
     * This is invoked by the sessions on {@link Session#disconnect}.
     */
    public void unregisterSession(@NonNull final Session session) {
        synchronized (sessionPool) {
            sessionPool.remove(session);
        }
    }

}
