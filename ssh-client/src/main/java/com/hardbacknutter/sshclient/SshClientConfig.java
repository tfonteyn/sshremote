package com.hardbacknutter.sshclient;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.compression.SshDeflater;
import com.hardbacknutter.sshclient.compression.SshInflater;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchange;
import com.hardbacknutter.sshclient.macs.SshMac;
import com.hardbacknutter.sshclient.userauth.UserAuth;
import com.hardbacknutter.sshclient.utils.BaseConfig;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * <h2>Algorithm configuration</h2>
 * <p>
 * These options contain a (comma-separated, without spaces)
 * list of algorithms, which will be offered to the server, and
 * from which one will be selected by negotiation during key exchange.
 * These should confirm to the format defined by RFC 4250, and be
 * accompanied by an "implementation" option.
 * <h3>Key exchange algorithms: {@link KeyExchange}</h3>
 * <h3>User Authentication methods: {@link UserAuth}</h3>
 *
 * <h3>Symmetric Encryption algorithms: {@link SshCipher}</h3>
 * <dl>
 * <dt>{@code cipher.s2c}</dt>
 * <dd>encryption algorithms used for server-to-client transport.
 * <dt>{@code cipher.c2s}</dt>
 * <dd>encryption algorithms used for client-to-server transport.
 * <dt>{@code class.check.ciphers}</dt>
 * <dd>A list of Ciphers which should be first checked for
 *     availability. All ciphers in this list which are not working will be removed
 *     from the {@code ciphers.c2s} and {@code ciphers.s2c} lists before sending these
 *     to the server in a KEX_INIT message.</dd>
 * </dl>
 *
 * <h3>Message Authentication Code algorithms: {@link SshMac}</h3>
 * <h3>Compression: {@link SshDeflater} and {@link SshInflater}</h3>
 * <p>
 * During key exchange, the first option in the client's list
 * (i.e. the option value) which also appears on the server's list
 * will be chosen for each algorithm. Thus the order matters here.
 * </p>
 * <h3 id="config-impl">Implementation classes</h3>
 * <p>The following options contain the class name of
 *    classes implementing a specific algorithm. They should
 *    implement the interface or abstract class mentioned here.
 * <p>
 *   The classes must be findable using the class loader which loaded
 *   the library (e.g. by a simple {@link Class#forName} inside
 *   the library classes), and must have a no-argument constructor, which
 *   will be called to instantiate the objects needed. Then the actual
 *   interface methods will be used.
 * </p>
 */
@SuppressWarnings("unused")
public interface SshClientConfig
        extends BaseConfig {

    /**
     * Get the configured {@link Logger}.
     *
     * @return logger
     */
    @NonNull
    Logger getLogger();

    /**
     * Set a {@link Logger}.
     *
     * @param logger to use
     */
    void setLogger(@Nullable Logger logger);

    /**
     * Get the configured {@link Random}.
     *
     * @return instance
     *
     * @throws NoSuchAlgorithmException on failure to init the instance
     */
    @NonNull
    Random getRandom()
            throws NoSuchAlgorithmException;

    /**
     * Get a map with all options.
     *
     * @return map
     */
    @NonNull
    Map<String, String> getAll();

    /**
     * Add/set multiple configuration options at once.
     * The given map should only contain Strings.
     * <p>
     * The values are copied into the existing configuration.
     *
     * @param map with values
     *
     * @see #putString(String, String)
     */
    void putAll(@NonNull Map<String, String> map);

    /**
     * Put a configuration {@link String} option.
     *
     * @param key   the key for the configuration option
     * @param value to set
     */
    void putString(@NonNull String key,
                   @NonNull String value);

    /**
     * Convenience method / code clarify. Add a class definition to the configuration.
     *
     * @param key   the key for the configuration option
     * @param clazz the class
     */
    default void putClass(@NonNull final String key,
                          @NonNull final Class<?> clazz) {
        putString(key, clazz.getCanonicalName());
    }
}
