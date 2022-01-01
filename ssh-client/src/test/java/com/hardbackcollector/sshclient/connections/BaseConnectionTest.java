package com.hardbackcollector.sshclient.connections;

import com.hardbackcollector.sshclient.DbgJLogger;
import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.kex.KexProposal;
import com.hardbackcollector.sshclient.utils.ImplementationFactory;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class BaseConnectionTest {

    protected static final SecureRandom RANDOM = new SecureRandom();
    private static final Logger LOGGER = new DbgJLogger();

    protected static final String HOST = "192.168.0.203";
    protected static final String USERNAME = "tom";
    protected static final String PASSWORD = "tom";

    protected static final int PORT = 22;
    protected static final String TEST_RESOURCES = "src/test/resources/";
    protected static final String[] ZIPPER = {
            KexProposal.COMPRESSION_NONE,
            KexProposal.COMPRESSION_ZLIB_OPENSSH_COM,
            KexProposal.COMPRESSION_ZLIB
    };
    static final String[] kexAlg = {"curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group14-sha1"};
    static final String[] sigAlg = {"ssh-rsa",
            "rsa-sha2-256",
            "rsa-sha2-512",
            "ecdsa-sha2-nistp256",
            "ssh-ed25519",
            // "ecdsa-sha2-nistp384",
            // "ecdsa-sha2-nistp521",
            // "ssh-ed448"
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
