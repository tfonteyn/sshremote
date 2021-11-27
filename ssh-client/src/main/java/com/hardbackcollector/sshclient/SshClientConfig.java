package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ciphers.SshCipher;
import com.hardbackcollector.sshclient.compression.SshDeflater;
import com.hardbackcollector.sshclient.compression.SshInflater;
import com.hardbackcollector.sshclient.kex.keyexchange.KeyExchange;
import com.hardbackcollector.sshclient.macs.SshMac;
import com.hardbackcollector.sshclient.userauth.UserAuth;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * <h3>Algorithm configuration</h3>
 * <p>
 * These options contain a (comma-separated, without spaces)
 * list of algorithms, which will be offered to the server, and
 * from which one will be selected by negotiation during key exchange.
 * These should confirm to the format defined by RFC 4250, and be
 * accompanied by an "implementation" option.
 *
 * <h4>Key exchange algorithms: {@link KeyExchange}</h4>
 * <h4>User Authentication methods: {@link UserAuth}</h4>
 *
 * <h4>Symmetric Encryption algorithms: {@link SshCipher}</h4>
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
 * <h4>Message Authentication Code algorithms: {@link SshMac}</h4>
 * <h4>Compression: {@link SshDeflater} and {@link SshInflater}</h4>
 * <p>
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
public interface SshClientConfig {

    @NonNull
    Map<String, String> getAll();

    /**
     * Add/set multiple configuration options at once.
     * The given hashtable should only contain Strings.
     *
     * @see #putString(String, String)
     */
    void putAll(@NonNull final Map<String, String> newConf);

    /**
     * Put a configuration string.
     *
     * @param key   the key for the configuration option
     * @param value to set
     */
    void putString(@NonNull final String key,
                   @NonNull final String value);

    /**
     * Convenience method / code clarify. Add a class definition to the configuration.
     *
     * @param configKey config key
     * @param clazz     the class
     */
    default void putClass(@NonNull final String configKey,
                          @NonNull final Class<?> clazz) {
        putString(configKey, clazz.getCanonicalName());
    }

    /**
     * Retrieves a configuration option.
     * <p>
     * If an option is not set, this method
     * returns the value set at the parent configuration level.
     * i.e. if a value is retrieved from the {@link Session}
     * but it's not there, the global value will be returned.
     *
     * @param key the key for the configuration option
     * @return the value corresponding to the key.
     */
    @Nullable
    String getString(@NonNull final String key);


    default boolean contains(@NonNull final String key) {
        final String s = getString(key);
        return s != null && !s.isBlank();
    }

    default int getIntValue(@NonNull final String key,
                            final int defValue) {
        final String s = getString(key);
        if (s != null) {
            try {
                return Integer.parseInt(s);
            } catch (final NumberFormatException e) {
                if (SshClient.getLogger().isEnabled(Logger.ERROR)) {
                    SshClient.getLogger()
                            .log(Logger.ERROR, "Invalid value for key=" + key + ": " + s);
                }
            }
        }
        return defValue;
    }

    default boolean getBooleanValue(@NonNull final String key,
                                    final boolean defValue) {
        final String s = getString(key);
        if (s != null) {
            return "true".equalsIgnoreCase(s) || "yes".equalsIgnoreCase(s);
        }
        return defValue;
    }

    @NonNull
    default String getString(@NonNull final String key,
                             @NonNull final String defValue) {
        final String s = getString(key);
        return s != null && !s.isBlank() ? s : defValue;
    }

    @NonNull
    default List<String> getStringList(@NonNull final String key) {
        final String s = getString(key);
        return s != null ? Arrays.asList(s.split(",")) : new ArrayList<>();
    }

    @NonNull
    default List<String> getStringList(@NonNull final String key,
                                       @NonNull final String defValue) {
        final String s = getString(key);
        if (s != null) {
            return Arrays.asList(s.split(","));
        }
        final List<String> list = new ArrayList<>();
        list.add(defValue);
        return list;
    }


    int getNumberOfPasswordPrompts();

    /**
     * The list of algorithms we can accept for public key authentication.
     *
     * @return the list; can be empty.
     */
    @NonNull
    List<String> getPublicKeyAcceptedAlgorithms();

    @NonNull
    Random getRandom()
            throws NoSuchAlgorithmException;

}
