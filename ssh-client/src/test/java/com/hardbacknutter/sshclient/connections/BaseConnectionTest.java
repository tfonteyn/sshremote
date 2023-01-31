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
    public static final String USERNAME = "test";
    public static final String PASSWORD = "test";

    protected static final int PORT = 22;
    protected static final String[] ZIPPER = {
            KexProposal.COMPRESSION_NONE,
            KexProposal.COMPRESSION_ZLIB_OPENSSH_COM,
            KexProposal.COMPRESSION_ZLIB
    };
    static final String[] kexAlg = {
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1"};
    static final String[] sigAlg = {
            Constants.SSH_RSA,
            Constants.RSA_SHA_2_256,
            Constants.RSA_SHA_2_512,
            Constants.ECDSA_SHA_2_NISTP_256,
            Constants.SSH_ED_25519
    };

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

    private void setupJSch() {

        // Pick ONE SET of TWO lines, comment out the others.
        // sshClient.setConfig(KexEnv.PROPOSAL_ENC_ALGS_STOC, "chacha20-poly1305@openssh.com");
        // sshClient.setConfig(KexEnv.PROPOSAL_ENC_ALGS_CTOS, "chacha20-poly1305@openssh.com");

        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_STOC, "aes128-ctr");
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_CTOS, "aes128-ctr");

        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_STOC, "aes192-ctr");
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_CTOS, "aes192-ctr");
        //
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_STOC, "aes256-ctr");
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_CTOS, "aes256-ctr");
        //
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_STOC, "aes128-gcm@openssh.com");
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_CTOS, "aes128-gcm@openssh.com");
        //
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_STOC, "aes256-gcm@openssh.com");
        // sshClient.setConfig(CryptoEnv.PROPOSAL_ENC_ALGS_CTOS, "aes256-gcm@openssh.com");

        // Pick ONE SET of TWO lines, comment out the others.
        // sshClient.setConfig(CryptoEnv.PROPOSAL_MAC_ALGS_CTOS, "hmac-sha1");
        // sshClient.setConfig(CryptoEnv.PROPOSAL_MAC_ALGS_STOC, "hmac-sha1");

    }
}
