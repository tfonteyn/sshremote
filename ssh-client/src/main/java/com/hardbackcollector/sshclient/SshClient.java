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
package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.hostconfig.HostConfigRepository;
import com.hardbackcollector.sshclient.hostkey.HostKeyRepository;
import com.hardbackcollector.sshclient.hostkey.KnownHosts;
import com.hardbackcollector.sshclient.identity.Identity;
import com.hardbackcollector.sshclient.identity.IdentityImpl;
import com.hardbackcollector.sshclient.identity.IdentityRepository;
import com.hardbackcollector.sshclient.identity.IdentityRepositoryWrapper;
import com.hardbackcollector.sshclient.identity.InMemoryIdentityRepository;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.userauth.SshAuthException;
import com.hardbackcollector.sshclient.utils.SshClientConfigImpl;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

/**
 * This class is the central entry/configuration point.
 * It serves as a factory for {@link Session} objects which in turn can provide a Channel.
 * <ul>
 *      <li>Set any global options using {@link #setConfig}</li>
 *      <li>Instantiate a class object</li>
 *      <li>If using public-key authentication, call one of the {@link #addIdentity}
 *          methods for adding your key(s).</li>
 *      <li>Use {@link #setKnownHosts setKnownHosts} to enable
 *          checking of host keys using a "known_hosts" file</li>
 *      <li>Use {@link #getSession} to start a new Session.</li>
 * </ul>
 */
public class SshClient {

    /**
     * The standard Java resource bundle with (translated) messages.
     */
    public static final String USER_MESSAGES = "msg.usermessages";

    /**
     * client version: SSH-protoversion-softwareversion SP comments CR LF
     * The CR+LF is added when the version is send to the server.
     *
     * @see Session#setClientVersion(String)
     */
    public static final String VERSION = "SSH-2.0-JSCH-2.0";

    /**
     * Boolean:
     * If {@link true}, BC is used for all operations;
     * If {@link false}, the JDK has priority and BC handles only what the JDK cannot.
     */
    private static final String PREFER_BOUNCY_CASTLE = "prefer_bouncycastle";
    private static final Logger DEVNULL = new Logger() {
        @Override
        public boolean isEnabled(final int level) {
            return false;
        }

        @Override
        public void log(final int level,
                        @NonNull final String message) {
        }
    };
    private static Logger logger = DEVNULL;

    /**
     * A pool of all sessions currently active for this instance.
     * A {@link Session} is added when it's created, and removed upon {@link Session#disconnect()}.
     * <p>
     * Not actually used/checked for now, but it provides a way to track any sessions still open.
     * TODO: maybe add a 'disconnect' to the client ?
     */
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    private final Set<Session> sessionPool = new HashSet<>();

    private final SshClientConfigImpl config;


    /**
     * Public key authentication.
     */
    @NonNull
    private final IdentityRepository defaultIdentityRepository;
    /**
     * Public key authentication.
     */
    @NonNull
    private IdentityRepository identityRepository;

    /**
     * A repository with custom sets of configuration details for specific hosts.
     */
    @Nullable
    private HostConfigRepository hostConfigRepository;

    /**
     * HostKey verification.
     */
    @Nullable
    private HostKeyRepository hostKeyRepository;

    private boolean globalIdentitiesLoaded;

    public SshClient() {
        // create the default configuration
        config = new SshClientConfigImpl();

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

            if (pos == -1 && getLogger().isEnabled(Logger.DEBUG)) {
                getLogger().log(Logger.DEBUG, "BouncyCastleProvider already installed");
            }
        } catch (final SecurityException e) {
            if (getLogger().isEnabled(Logger.FATAL)) {
                getLogger().log(Logger.FATAL, "BouncyCastleProvider failed to install", e);
            }
        }
    }

    /**
     * returns the current Logger.
     */
    @NonNull
    public static Logger getLogger() {
        return logger;
    }

    /**
     * sets the Logger to be used by this library.
     *
     * @param logger the new logger. If {@code null}, we use a builtin
     *               Logger which logs nothing.
     * @see com.hardbackcollector.sshclient.Logger
     */
    public static void setLogger(@Nullable Logger logger) {
        if (logger == null) {
            logger = DEVNULL;
        }
        SshClient.logger = logger;
    }


    /**
     * @param key   the option name.
     * @param value the option value.
     * @see Session#setConfig
     * @see SshClientConfig#getIntValue
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
     * The given hashtable should only contain Strings.
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
     * Retrieves a default configuration option.
     *
     * @param key key for the configuration.
     * @return config value
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
     * @return a new instance of {@code Session}.
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
     * @return a new instance of {@code Session}.
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
     * @return a new instance of {@code Session}.
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
     *                        {@link HostConfigRepository.HostConfig} for the given host.
     *                        If not set, the {@code host} will be used.
     * @return a new instance of {@code Session}.
     * @throws SshAuthException if {@code username} or {@code host} are invalid.
     * @see HostConfigRepository
     */
    @NonNull
    public Session getSession(@Nullable final String username,
                              @NonNull final String host,
                              final int port,
                              @Nullable final String hostNameOrAlias)
            throws IOException, GeneralSecurityException, SshAuthException {

        final HostConfigRepository.HostConfig hostConfig;

        if (hostConfigRepository != null) {
            initGlobalIdentities();
            hostConfig = hostConfigRepository
                    .getHostConfig(hostNameOrAlias != null ? hostNameOrAlias : host);
        } else {
            hostConfig = null;// new SimpleHostConfig(host, port, username);
        }

        final Session session = new SessionImpl(this, config,
                username, host, port,
                // public key auth
                identityRepository,
                // host key verification
                getHostKeyRepository(),
                // extra/specific config for the specified host
                hostConfig);

        synchronized (sessionPool) {
            sessionPool.add(session);
        }
        return session;
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
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
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
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     * @throws InvalidKeyException if a {@code passphrase} was given, but decryption failed
     */
    @SuppressWarnings("WeakerAccess")
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
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
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
     * <p>
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
                        .getIdentityFiles();

                for (final String prvKeyFilename : fileNames) {
                    addIdentity(prvKeyFilename, null, null);
                }

                globalIdentitiesLoaded = true;
            }
        }
    }

    /**
     * INTERNAL USE ONLY.
     * <p>
     * Removes a session from our session pool.
     * This is invoked by the sessions on {@link Session#disconnect}.
     */
    public void onSessionDisconnected(@NonNull final Session session) {
        synchronized (sessionPool) {
            sessionPool.remove(session);
        }
    }

}
