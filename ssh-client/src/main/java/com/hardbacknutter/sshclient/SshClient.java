package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Map;

import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfigRepository;
import com.hardbacknutter.sshclient.hostkey.HostKeyRepository;
import com.hardbacknutter.sshclient.hostkey.KnownHosts;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.userauth.SshAuthException;

/**
 * This is the central entry/configuration point.
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
 *
 * @see SshClientFactory
 */
@SuppressWarnings("UnusedReturnValue")
public interface SshClient {

    /**
     * returns the current client {@link Logger}.
     *
     * @return the current logger
     */
    @NonNull
    Logger getLogger();

    /**
     * Sets the {@link Logger} to be used by this client.
     * Existing sessions will keep using the logger as set when they where created.
     *
     * @param logger the new logger. If {@code null}, we use a builtin
     *               Logger which logs nothing.
     *
     * @see Session#setLogger(Logger)
     */
    void setLogger(@Nullable Logger logger);

    /**
     * Set a configuration {@link String} option.
     *
     * @param key   the key for the configuration option
     * @param value to set
     *
     * @see Session#setConfig(String, String)
     * @see SshClientConfig#putString(String, String)
     */
    void setConfig(@NonNull String key,
                   @NonNull String value);

    /**
     * Retrieve the configuration object.
     *
     * @return config
     */
    @NonNull
    SshClientConfig getConfig();

    /**
     * Sets multiple default configuration options at once.
     * The given hashtable should only contain Strings. Values are copied.
     *
     * @see #setConfig(String, String)
     */
    void setConfig(@NonNull Map<String, String> newConf);

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
    String getConfig(@NonNull String key);

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
    @Nullable
    HostConfigRepository getHostConfigRepository();

    void setHostConfigRepository(@Nullable HostConfigRepository configRepository);

    @NonNull
    HostKeyRepository getHostKeyRepository();

    /**
     * Sets a generic/custom {@link HostKeyRepository}.
     * This will be used by sessions {@linkplain Session#connect connected}
     * in the future to validate the host keys offered by the remote hosts.
     *
     * @see HostKeyRepository
     * @see KnownHosts
     */
    void setHostKeyRepository(@Nullable HostKeyRepository repository);

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
    void setKnownHosts(@NonNull String filename)
            throws IOException, GeneralSecurityException;

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
    void setKnownHosts(@NonNull InputStream stream)
            throws IOException, GeneralSecurityException;

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
    Session getSession(@NonNull String host)
            throws IOException, GeneralSecurityException, SshAuthException;

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
    Session getSession(@Nullable String username,
                       @NonNull String host)
            throws SshAuthException, IOException, GeneralSecurityException;

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
    Session getSession(@Nullable String username,
                       @NonNull String host,
                       int port)
            throws SshAuthException, IOException, GeneralSecurityException;

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
    Session getSession(@Nullable String username,
                       @NonNull String host,
                       int port,
                       @Nullable String hostNameOrAlias)
            throws IOException, GeneralSecurityException, SshAuthException;

    @NonNull
    IdentityRepository getIdentityRepository();

    /**
     * Sets the {@code identityRepository}, which will be referred
     * in the public key authentication.
     *
     * @param identityRepository if {@code null} is given, the default repository,
     *                           which usually refers to ~/.ssh/, will be used.
     *
     * @see #getIdentityRepository()
     */
    void setIdentityRepository(
            @Nullable IdentityRepository identityRepository);

    /**
     * Adds an identity to be used for public-key authentication.
     * <p>
     * If a file with the same name and suffix {@code .pub}.
     * exists, it will be parsed for the public key.
     *
     * @param privateKeyFilename the file name of the private key file.
     *                           This is also used as the identifying name of the key.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     */
    boolean addIdentity(@NonNull String privateKeyFilename)
            throws IOException, GeneralSecurityException;

    /**
     * Adds a file-based identity to be used for public-key authentication.
     * <p>
     * If a passphrase is provided, decryption wil be attempted
     * before registering it into identityRepository, and if failing this method will throw.
     *
     * @param privateKeyFilename the file name of the private key file.
     *                           This is also used as the identifying name of the key.
     * @param publicKeyFilename  the file name of the public key file.
     * @param passphrase         the passphrase necessary to access the private key.
     *
     * @return {@code true} if the identity was added successfully, {@code false} otherwise.
     *
     * @throws InvalidKeyException if a {@code passphrase} was given, but decryption failed
     */
    boolean addIdentity(@NonNull String privateKeyFilename,
                        @Nullable String publicKeyFilename,
                        @Nullable byte[] passphrase)
            throws IOException, GeneralSecurityException;

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
    boolean addIdentity(@NonNull String name,
                        @NonNull byte[] prvKey,
                        @Nullable byte[] pubKey,
                        @Nullable byte[] passphrase)
            throws IOException, GeneralSecurityException;

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
    boolean addIdentity(@NonNull Identity identity,
                        @Nullable byte[] passphrase)
            throws GeneralSecurityException, IOException;
}
