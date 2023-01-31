package com.hardbacknutter.sshclient.hostkey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.StringJoiner;

/**
 * The <strong>public</strong> key of a SSH server.
 * This class encapsulates a list of host names and the public
 * key of this host in one object.
 *
 * @see HostKeyRepository
 */
public class HostKey {

    /**
     * The default hash algorithm to use for creating fingerprints.
     * Valid options are: "md5", "SHA-224","SHA-256","SHA-384","SHA-5126"
     * The default is "SHA-256".
     * <p>
     * Note these are in JDK standard notation, and not openssh without the dash.
     */
    private static final String DEFAULT_FINGERPRINT_HASH = "SHA-256";


    // LOWERCASE
    private static final String[] HEX_ARRAY = {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"
    };

    /** prefix, e.g. "@revoked" or "@cert-authority". */
    @NonNull
    private final String marker;
    @NonNull
    private final String comment;
    @NonNull
    private final String type;
    // The key will only be {@code null} if the type is not known
    @Nullable
    private final byte[] key;

    /**
     * Hostnames is a comma-separated list of patterns (‘*’ and ‘?’ act as wildcards)
     * <p>
     * A hostname or address may optionally be enclosed within ‘[’ and ‘]’ brackets then
     * followed by ‘:’ and a non-standard port number.
     */
    @SuppressWarnings("WeakerAccess")
    @NonNull
    protected String hostnames;

    /**
     * Create a host key by guessing it's type from the data.
     *
     * @param host the host name (or names, as a comma-separated list)
     * @param key  the key data.
     */
    public HostKey(@NonNull final String host,
                   @Nullable final byte[] key)
            throws InvalidKeyException {
        this("", host, null, key, null);
    }

    /**
     * Create a host key with the given type.
     *
     * @param host the host name (or names, as a comma-separated list)
     * @param type the type.
     * @param key  the key data.
     */
    public HostKey(@NonNull final String host,
                   @NonNull final String type,
                   @Nullable final byte[] key)
            throws InvalidKeyException {
        this("", host, type, key, null);
    }

    /**
     * @param marker  prefix, e.g. "@revoked"
     * @param host    the host name (or names, as a comma-separated list)
     * @param type    if {@code null}, we'll try to guess the type from the key data.
     * @param key     the key data.
     * @param comment optional user comment
     */
    public HostKey(@NonNull final String marker,
                   @NonNull final String host,
                   @Nullable final String type,
                   @Nullable final byte[] key,
                   @Nullable final String comment)
            throws InvalidKeyException {

        if (type == null && key == null) {
            throw new InvalidKeyException("Must have either type or key set");
        }

        if (type == null) {
            this.type = HostKeyAlgorithm.parseType(key);
        } else {
            this.type = HostKeyAlgorithm.parseType(type);
        }

        this.marker = marker;
        this.hostnames = host;
        this.key = key;
        this.comment = comment != null ? comment : "";
    }

    /**
     * Private; use {@link #createUnknown(String)} to make it clear.
     *
     * @param line full line to store (probably a comment line)
     */
    private HostKey(@NonNull final String line) {
        this.marker = "";
        this.hostnames = "";
        this.type = "";
        this.key = null;
        this.comment = line;
    }

    static HostKey createUnknown(@NonNull final String line) {
        return new HostKey(line);
    }

    /**
     * returns the key's fingerprint (i.e. a lowercase hexadecimal
     * representation of the hash of the key.)
     * <p>
     * Uses the configured hash algorithm.
     */
    @NonNull
    public static String getFingerPrint(@NonNull final SshClientConfig config,
                                        @NonNull final byte[] data)
            throws NoSuchAlgorithmException {

        String algorithm = config.getString(HostConfig.FINGERPRINT_HASH);
        if (algorithm == null || algorithm.isBlank()) {
            algorithm = DEFAULT_FINGERPRINT_HASH;
        }
        return getFingerPrint(algorithm, data);
    }

    /**
     * Returns the key's fingerprint using the specified hash algorithm.
     * <p>
     * SHA-*: a base64 string of the hash of the key
     * MD5: lowercase hexadecimal representation of the hash of the key
     */
    @NonNull
    public static String getFingerPrint(@NonNull final String algorithm,
                                        @NonNull final byte[] data)
            throws NoSuchAlgorithmException {

        final MessageDigest md = MessageDigest.getInstance(algorithm);
        try {
            md.update(data, 0, data.length);

            if ("MD5".equalsIgnoreCase(algorithm)) {
                final StringJoiner sb = new StringJoiner(":");
                for (final byte b : md.digest()) {
                    sb.add(HEX_ARRAY[b >>> 4 & 0xf] + HEX_ARRAY[b & 0xf]);
                }
                return sb.toString();
            }

            final String fp = new String(Base64.getEncoder()
                                               .encode(md.digest()), StandardCharsets.UTF_8);
            if (fp.endsWith("=")) {
                return fp.substring(0, fp.length() - 1);
            }
            return fp;

        } catch (final Exception e) {
            return "???";
        }
    }


    @NonNull
    public List<String> getHosts() {
        return Arrays.asList(hostnames.split(","));
    }

    public void setHosts(@NonNull final List<String> hostnames) {
        this.hostnames = String.join(",", hostnames);
    }

    @NonNull
    String getMarker() {
        return marker;
    }

    /**
     * Get the type of the key; will be {@code ""} for comment-only keys
     *
     * @return the type of the key.
     */
    @NonNull
    public String getType() {
        return type;
    }

    /**
     * Get the name of the host(s).
     *
     * @return the host name (or names, as a comma-separated list)
     */
    @NonNull
    String getHostnames() {
        return hostnames;
    }

    @Nullable
    byte[] getKey() {
        return key;
    }

    /**
     * Get a base64-representation of the key.
     *
     * @return base 64 string
     */
    @NonNull
    String getEncodedKey() {
        final byte[] str = Base64.getEncoder().encode(key);
        return new String(str, 0, str.length, StandardCharsets.UTF_8);
    }

    @NonNull
    String getComment() {
        return comment;
    }

    /**
     * Check if the key applies to the given host name.
     */
    public boolean isMatching(@NonNull final String host) {
        for (final String hostname : hostnames.split(",")) {
            if (hostname.contains("*") || hostname.contains("?")) {
                // wildcards which are not regex... urg...
                if (host.matches(hostname.replace(".", "\\.")
                                         .replace("*", ".*")
                                         .replace("?", "."))) {
                    return true;
                }

            } else if (hostname.equalsIgnoreCase(host)) {
                return true;
            }
        }
        return false;
    }
}
