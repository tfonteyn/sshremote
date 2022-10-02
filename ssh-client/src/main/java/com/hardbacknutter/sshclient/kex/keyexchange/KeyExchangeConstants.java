package com.hardbacknutter.sshclient.kex.keyexchange;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4419">
 * RFC 4419, Diffie-Hellman Group Exchange for the Secure Shell (SSH)</a>
 * @see <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.toc">
 * Key Exchange (KEX) Method Updates and Recommendations</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8.1">
 * RFC 4253 SSH Transport Layer Protocol, section 8. Diffie-Hellman Key Exchange</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2409#section-6.2">
 * RFC 2409 The Internet Key Exchange (IKE), section 6.2. Second Oakley Group</a>
 * @see <a href="https://tools.ietf.org/id/draft-ietf-curdle-ssh-kex-sha2-09.html#rfc.toc">
 * Key Exchange (KEX) Method Updates and Recommendations</a>
 */
public final class KeyExchangeConstants {

    public static final String DIFFIE_HELLMAN_GROUP_1_SHA_1 =
            "diffie-hellman-group1-sha1";
    public static final String DIFFIE_HELLMAN_GROUP_14_SHA_1 =
            "diffie-hellman-group14-sha1";
    public static final String DIFFIE_HELLMAN_GROUP_14_SHA_224_SSH_COM =
            "diffie-hellman-group14-sha224@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_14_SHA_256 =
            "diffie-hellman-group14-sha256";
    public static final String DIFFIE_HELLMAN_GROUP_14_SHA_256_SSH_COM =
            "diffie-hellman-group14-sha256@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_15_SHA_256_SSH_COM =
            "diffie-hellman-group15-sha256@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_15_SHA_384_SSH_COM =
            "diffie-hellman-group15-sha384@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_15_SHA_512 =
            "diffie-hellman-group15-sha512";
    public static final String DIFFIE_HELLMAN_GROUP_16_SHA_384_SSH_COM =
            "diffie-hellman-group16-sha384@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_16_SHA_512 =
            "diffie-hellman-group16-sha512";
    public static final String DIFFIE_HELLMAN_GROUP_16_SHA_512_SSH_COM =
            "diffie-hellman-group16-sha512@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_17_SHA_512 =
            "diffie-hellman-group17-sha512";
    public static final String DIFFIE_HELLMAN_GROUP_18_SHA_512 =
            "diffie-hellman-group18-sha512";
    public static final String DIFFIE_HELLMAN_GROUP_18_SHA_512_SSH_COM =
            "diffie-hellman-group18-sha512@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_1 =
            "diffie-hellman-group-exchange-sha1";
    public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_224_SSH_COM =
            "diffie-hellman-group-exchange-sha224@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256 =
            "diffie-hellman-group-exchange-sha256";
    public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256_SSH_COM =
            "diffie-hellman-group-exchange-sha256@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_384_SSH_COM =
            "diffie-hellman-group-exchange-sha384@ssh.com";
    public static final String DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_512_SSH_COM =
            "diffie-hellman-group-exchange-sha512@ssh.com";

    public static final String ECDH_SHA_2_NISTP_256 = "ecdh-sha2-nistp256";
    public static final String ECDH_SHA_2_NISTP_384 = "ecdh-sha2-nistp384";
    public static final String ECDH_SHA_2_NISTP_521 = "ecdh-sha2-nistp521";

    public static final String CURVE_448_SHA_512 = "curve448-sha512";

    public static final String CURVE_25519_SHA_256 = "curve25519-sha256";
    public static final String CURVE_25519_SHA_256_LIBSSH_ORG = "curve25519-sha256@libssh.org";

    private KeyExchangeConstants() {
    }
}
