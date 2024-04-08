package com.hardbacknutter.sshclient.transport;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfigRepository;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.hostkey.KnownHosts;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityImpl;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.identity.IdentityRepositoryWrapper;
import com.hardbacknutter.sshclient.identity.InMemoryIdentityRepository;
import com.hardbacknutter.sshclient.userauth.SshAuthException;
import com.hardbacknutter.sshclient.utils.SshClientConfigImpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SshClientImpl
        implements SshClient {

    /**
     * client version: {@code SSH-protoversion-softwareversion SP comments CR LF}
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
     *         RFC 4253, section4.2</a>
     */
    static final String VERSION = "SSH-2.0-JSCH_2.0";

    /**
     * Boolean:
     * If {@code true}, BC is used for all operations;
     * If {@code false}, the JDK has priority and BC handles only what the JDK cannot.
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
     *
     * @param logger to use; can be {@code null} for no logging at all.
     */
    public SshClientImpl(@Nullable final Logger logger) {
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
                config.getLogger().log(Logger.DEBUG, () ->
                        "BouncyCastleProvider already installed");
            }
        } catch (final SecurityException e) {
            config.getLogger().log(Logger.FATAL, e, () ->
                    "BouncyCastleProvider failed to install");
        }
    }

    @Override
    @NonNull
    public Logger getLogger() {
        return config.getLogger();
    }

    @Override
    public void setLogger(@Nullable final Logger logger) {
        config.setLogger(logger);
    }

    @Override
    public void setConfig(@NonNull final String key,
                          @NonNull final String value) {
        config.putString(key, value);
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
    @Nullable
    public String getConfig(@NonNull final String key) {
        synchronized (config) {
            return config.getString(key);
        }
    }

    @Override
    @SuppressWarnings("WeakerAccess")
    @Nullable
    public HostConfigRepository getHostConfigRepository() {
        return hostConfigRepository;
    }

    @Override
    @SuppressWarnings("WeakerAccess")
    public void setHostConfigRepository(@Nullable final HostConfigRepository configRepository) {
        this.hostConfigRepository = configRepository;
    }

    @Override
    @SuppressWarnings("WeakerAccess")
    @NonNull
    public HostKeyRepository getHostKeyRepository() {
        if (hostKeyRepository == null) {
            hostKeyRepository = new KnownHosts(config);
        }
        return hostKeyRepository;
    }

    @Override
    public void setHostKeyRepository(@Nullable final HostKeyRepository repository) {
        hostKeyRepository = repository;
    }

    @Override
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

    @Override
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

    @Override
    @NonNull
    public Session getSession(@NonNull final String host)
            throws IOException, GeneralSecurityException, SshAuthException {
        return getSession(null, host, 0, null);
    }

    @Override
    @NonNull
    public Session getSession(@Nullable final String username,
                              @NonNull final String host)
            throws SshAuthException, IOException, GeneralSecurityException {
        return getSession(username, host, 0, null);
    }

    @Override
    @NonNull
    public Session getSession(@Nullable final String username,
                              @NonNull final String host,
                              final int port)
            throws SshAuthException, IOException, GeneralSecurityException {
        return getSession(username, host, port, null);
    }

    @Override
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

    @Override
    @NonNull
    public synchronized IdentityRepository getIdentityRepository() {
        return identityRepository;
    }

    @Override
    public synchronized void setIdentityRepository(
            @Nullable final IdentityRepository identityRepository) {
        this.identityRepository = Objects
                .requireNonNullElse(identityRepository, defaultIdentityRepository);
    }

    @Override
    public boolean addIdentity(@NonNull final String privateKeyFilename)
            throws IOException, GeneralSecurityException {
        final Identity identity = IdentityImpl.fromFiles(config, privateKeyFilename);
        return addIdentity(identity, null);
    }

    @Override
    @SuppressWarnings("WeakerAccess")
    public boolean addIdentity(@NonNull final String privateKeyFilename,
                               @Nullable final String publicKeyFilename,
                               @Nullable final byte[] passphrase)
            throws IOException, GeneralSecurityException {
        final Identity identity = IdentityImpl.fromFiles(config, privateKeyFilename,
                                                         publicKeyFilename);
        return addIdentity(identity, passphrase);
    }

    @Override
    @SuppressWarnings({"WeakerAccess", "unused"})
    public boolean addIdentity(@NonNull final String name,
                               @NonNull final byte[] prvKey,
                               @Nullable final byte[] pubKey,
                               @Nullable final byte[] passphrase)
            throws IOException, GeneralSecurityException {
        final Identity identity = IdentityImpl.fromKeyData(config, name, prvKey, pubKey);
        return addIdentity(identity, passphrase);
    }

    @Override
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
     * <p>
     * Removes a session from our session pool.
     * This is invoked by the sessions on {@link Session#disconnect}.
     */
    void unregisterSession(@NonNull final Session session) {
        synchronized (sessionPool) {
            sessionPool.remove(session);
        }
    }
}
