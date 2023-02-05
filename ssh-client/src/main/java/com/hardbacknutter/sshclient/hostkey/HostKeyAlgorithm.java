package com.hardbacknutter.sshclient.hostkey;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Add extra keys on Ubuntu:
 * <pre>{@code
 *   cd /ect/ssh
 *   ssh-keygen -b 1024 -f ssh_host_dsa_key -t dsa -N ""
 *   ssh-keygen -b 384 -t ecdsa -N "" -f ssh_host_ecdsa384_key
 *   ssh-keygen -b 521 -t ecdsa -N "" -f ssh_host_ecdsa521_key
 *   }
 *   Then edit "sshd_config" and add:
 *   {@code
 *      # enabled the defaults:
 *      hostkey /etc/ssh/ssh_host_rsa_key
 *      hostkey /etc/ssh/ssh_host_ecdsa_key
 *      hostkey /etc/ssh/ssh_host_ed25519_key
 *      # add:
 *      hostkey /etc/ssh/ssh_host_dsa_key
 *      hostkey /etc/ssh/ssh_host_ecdsa384_key
 *      hostkey /etc/ssh/ssh_host_ecdsa521_key
 * }
 * </pre>
 */
@SuppressWarnings("WeakerAccess")
public final class HostKeyAlgorithm {

    /**
     * So is it DSS or DSA ?
     * The Digital Signature Algorithm (DSA) is published in the
     * Digital Signature Standard (DSS) by the NIST in FIPS 186.
     * <p>
     * As the string used in packets is "ssh-dss", we use DSS for the host key enum
     */
    public static final String SSH_DSS = "ssh-dss";


    public static final String SSH_ECDSA_SHA2_NISTP256 = "ecdsa-sha2-nistp256";
    public static final String SSH_ECDSA_SHA2_NISTP384 = "ecdsa-sha2-nistp384";
    public static final String SSH_ECDSA_SHA2_NISTP521 = "ecdsa-sha2-nistp521";

    public static final String SSH_ED25519 = "ssh-ed25519";
    public static final String SSH_ED448 = "ssh-ed448";

    /**
     * The RSA family.
     * <p>
     * The 256/512 strings ARE SEND to the server in the list of key algorithms
     * the client supports.
     * <p>
     * The wire protocol is however always "ssh-rsa" while
     * the 256/512 strings are used in signature wrappers to identify the hash function to use
     * for verification of the key.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8332">RFC 8332</a>
     */
    public static final String SSH_RSA = "ssh-rsa";
    public static final String SIG_ONLY_RSA_SHA2_256 = "rsa-sha2-256";
    public static final String SIG_ONLY_RSA_SHA2_512 = "rsa-sha2-512";

    public static final String SIG_ONLY_RSA_SHA_224_SSH_COM = "ssh-rsa-sha224@ssh.com";
    public static final String SIG_ONLY_RSA_SHA_256_SSH_COM = "ssh-rsa-sha256@ssh.com";
    public static final String SIG_ONLY_RSA_SHA_384_SSH_COM = "ssh-rsa-sha384@ssh.com";
    public static final String SIG_ONLY_RSA_SHA_512_SSH_COM = "ssh-rsa-sha512@ssh.com";


    /**
     * All <strong>concrete</strong> host key algorithm's that are used by KEX.
     */
    private static final String[] ALL = {
            SSH_DSS,
            SSH_RSA,
            SSH_ECDSA_SHA2_NISTP256,
            SSH_ECDSA_SHA2_NISTP384,
            SSH_ECDSA_SHA2_NISTP521,
            SSH_ED25519,
            SSH_ED448};

    private HostKeyAlgorithm() {
    }

    /**
     * Check if the given type is of the RSA family.
     *
     * @param type to check
     *
     * @return {@code true} if it's one of the RSA family
     */
    public static boolean isRSA(final String type) {
        return SSH_RSA.equals(type) ||
                SIG_ONLY_RSA_SHA2_256.equals(type) ||
                SIG_ONLY_RSA_SHA2_512.equals(type) ||
                SIG_ONLY_RSA_SHA_224_SSH_COM.equals(type) ||
                SIG_ONLY_RSA_SHA_256_SSH_COM.equals(type) ||
                SIG_ONLY_RSA_SHA_384_SSH_COM.equals(type) ||
                SIG_ONLY_RSA_SHA_512_SSH_COM.equals(type);
    }

    /**
     * Parse/check if the given algorithm name is a supported type.
     *
     * @param keyAlgorithm to check
     *
     * @return one of the constants with the algorithm name
     *
     * @throws InvalidKeyException if the type is not recognised/supported
     * @see #parseType(byte[])
     */
    @NonNull
    public static String parseType(@Nullable final String keyAlgorithm)
            throws InvalidKeyException {
        if (keyAlgorithm != null
                && Arrays.stream(ALL).anyMatch(type -> type.equalsIgnoreCase(keyAlgorithm))) {
            return keyAlgorithm;
        }
        throw new InvalidKeyException("key type " + keyAlgorithm + " not supported");
    }

    /**
     * Parse a binary key for the string header, and return the algorithm name.
     *
     * @param key to check
     *
     * @return one of the constants with the algorithm name
     *
     * @throws InvalidKeyException if the type is not recognised/supported
     * @see #parseType(String)
     */
    @NonNull
    public static String parseType(@NonNull final byte[] key)
            throws InvalidKeyException {
        if (key.length > 20) {
            if (key[8] == 'd') {
                // ssh-dss
                return SSH_DSS;

            } else if (key[8] == 'r') {
                // ssh-rsa
                return SSH_RSA;

            } else if (key[8] == 'e') {
                if (key[10] == '2') {
                    // ssh-ed25519
                    return SSH_ED25519;

                } else if (key[10] == '4') {
                    // ssh-ed448
                    return SSH_ED448;
                }
            } else if (key[8] == 'a') {
                if (key[20] == '2') {
                    // ecdsa-sha2-nistp256
                    return SSH_ECDSA_SHA2_NISTP256;

                } else if (key[20] == '3') {
                    // ecdsa-sha2-nistp384
                    return SSH_ECDSA_SHA2_NISTP384;

                } else if (key[20] == '5') {
                    // ecdsa-sha2-nistp521
                    return SSH_ECDSA_SHA2_NISTP521;
                }
            }
        }
        throw new InvalidKeyException("key type not supported");
    }
}
