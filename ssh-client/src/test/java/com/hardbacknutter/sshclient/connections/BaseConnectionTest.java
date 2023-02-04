package com.hardbacknutter.sshclient.connections;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;

/**
 * Test server:
 * <p>
 * WLS2 Ubuntu with OpenSSH installed.
 * Edit "/etc/ssh/sshd_config" with:
 * <pre>
 *      PubkeyAuthentication yes
 *      PasswordAuthentication yes
 * </pre>
 * <p>
 * Add a "test" user with password "test" and login as this user
 * <pre>
 * mkdir ~/.ssh
 * cd ~/.ssh
 * touch authorized_keys
 * chmod 600 authorized_keys
 * </pre>
 * Edit "~/.ssh/authorized_keys" and add one or more
 * public keys from the clients ~/.ssh/*.pub file(s)
 * <p>
 * Create "~/long.txt" with more than 4k of text. e.g. "help >long.txt" should do
 */
public class BaseConnectionTest {

    protected static final SecureRandom RANDOM = new SecureRandom();
    private static final Logger LOGGER = new DbgJLogger();

    protected static final String HOST = "172.18.15.121";
    protected static final String USERNAME = "test";
    public static final String PASSWORD = "test";

    protected static final int PORT = 22;
    protected static final String[] ZIPPER = {
            KexProposal.COMPRESSION_NONE,
            KexProposal.COMPRESSION_ZLIB_OPENSSH_COM,
            KexProposal.COMPRESSION_ZLIB
    };
    static final List<String> KEX_ALGS = List.of(
            Constants.KEX_ALG_CURVE_25519_SHA_256,
            Constants.KEX_ALG_CURVE_25519_SHA_256_LIBSSH_ORG,
            Constants.KEX_ALG_ECDH_SHA_2_NISTP_256,
            Constants.KEX_ALG_ECDH_SHA_2_NISTP_384,
            Constants.KEX_ALG_ECDH_SHA_2_NISTP_521,
            Constants.KEX_ALG_DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256,
            Constants.KEX_ALG_DIFFIE_HELLMAN_GROUP_16_SHA_512,
            Constants.KEX_ALG_DIFFIE_HELLMAN_GROUP_18_SHA_512,
            Constants.KEX_ALG_DIFFIE_HELLMAN_GROUP_14_SHA_256,
            Constants.KEX_ALG_DIFFIE_HELLMAN_GROUP_14_SHA_1);
    static final List<String> SIG_ALGS = List.of(
            Constants.SSH_RSA,
            Constants.RSA_SHA_2_256,
            Constants.RSA_SHA_2_512,
            Constants.ECDSA_SHA_2_NISTP_256,
            Constants.SSH_ED_25519);

    static final List<String> ENC_ALGS = List.of(
            Constants.ENC_ALG_CHACHA_20_POLY_1305_OPENSSH_COM,
            Constants.ENC_ALG_AES_128_CTR,
            Constants.ENC_ALG_AES_192_CTR,
            Constants.ENC_ALG_AES_256_CTR,
            Constants.ENC_ALG_AES_128_GCM_OPENSSH_COM,
            Constants.ENC_ALG_AES_256_GCM_OPENSSH_COM
    );

    static final List<String> MACS = List.of(
            Constants.HMAC_SHA_1
    );

    private static final String KNOWN_HOSTS = "C:/tmp/ssh/known_hosts";

    protected SshClient sshClient;

    /**
     * @param zipper one of {@link #ZIPPER}
     */
    protected void setup(final String zipper)
            throws IOException, GeneralSecurityException {
        sshClient = new SshClient(LOGGER);

        sshClient.setConfig(ImplementationFactory.PK_VALIDATE_ALGORITHM_CLASSES, "false");

        sshClient.setConfig(KexProposal.PROPOSAL_COMP_CTOS, zipper);
        sshClient.setConfig(KexProposal.PROPOSAL_COMP_STOC, zipper);

        //noinspection ResultOfMethodCallIgnored
        new File(KNOWN_HOSTS).createNewFile();
        sshClient.setKnownHosts(KNOWN_HOSTS);
        sshClient.setConfig("StrictHostKeyChecking", "no");
    }
}
