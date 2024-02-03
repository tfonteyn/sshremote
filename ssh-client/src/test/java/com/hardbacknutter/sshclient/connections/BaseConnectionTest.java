package com.hardbacknutter.sshclient.connections;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientFactory;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.kex.keyexchange.KeyExchangeConstants;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

public class BaseConnectionTest {

    protected static final SecureRandom RANDOM = new SecureRandom();
    private static final Logger LOGGER = new DbgJLogger();

    protected static final String[] ZIPPER = {
            KexProposal.COMPRESSION_NONE,
            KexProposal.COMPRESSION_ZLIB_OPENSSH_COM,
            KexProposal.COMPRESSION_ZLIB
    };
    static final List<String> KEX_ALGS = List.of(
            KeyExchangeConstants.CURVE_25519_SHA_256,
            KeyExchangeConstants.CURVE_25519_SHA_256_LIBSSH_ORG,
            KeyExchangeConstants.ECDH_SHA_2_NISTP_256,
            KeyExchangeConstants.ECDH_SHA_2_NISTP_384,
            KeyExchangeConstants.ECDH_SHA_2_NISTP_521,
            KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA_256,
            KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_16_SHA_512,
            KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_18_SHA_512,
            KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_256,
            KeyExchangeConstants.DIFFIE_HELLMAN_GROUP_14_SHA_1);
    static final List<String> SIG_ALGS = List.of(
            // 3x "ssh-rsa", but with different (standard) signature algorithms
            HostKeyAlgorithm.SSH_RSA,
            HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256,
            HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512,
            // still "ssh-rsa" but with non-standard signature algorithms
//            HostKeyAlgorithm.SIG_ONLY_RSA_SHA_224_SSH_COM,
//            HostKeyAlgorithm.SIG_ONLY_RSA_SHA_256_SSH_COM,
//            HostKeyAlgorithm.SIG_ONLY_RSA_SHA_384_SSH_COM,
//            HostKeyAlgorithm.SIG_ONLY_RSA_SHA_512_SSH_COM,

            HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256,
            HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384,
            HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521,

            HostKeyAlgorithm.SSH_ED25519,

            //HostKeyAlgorithm.SSH_ED448,

            HostKeyAlgorithm.SSH_DSS
    );

    static final List<String> ENC_ALGS = List.of(
            SshCipherConstants.CHACHA20_POLY1305_OPENSSH_COM,
            SshCipherConstants.AES_128_CTR,
            SshCipherConstants.AES_192_CTR,
            SshCipherConstants.AES_256_CTR,
            SshCipherConstants.AES_128_GCM_OPENSSH_COM,
            SshCipherConstants.AES_256_GCM_OPENSSH_COM
    );

    protected SshClient sshClient;

    /**
     * @param zipper one of {@link #ZIPPER}
     */
    protected void setup(final String zipper)
            throws IOException, GeneralSecurityException {
        sshClient = SshClientFactory.create(LOGGER);

        sshClient.setConfig(ImplementationFactory.PK_VALIDATE_ALGORITHM_CLASSES, "false");

        sshClient.setConfig(KexProposal.PROPOSAL_COMP_CTOS, zipper);
        sshClient.setConfig(KexProposal.PROPOSAL_COMP_STOC, zipper);

        //noinspection ResultOfMethodCallIgnored
        new File(Constants.KNOWN_HOSTS).createNewFile();
        sshClient.setKnownHosts(Constants.KNOWN_HOSTS);
        sshClient.setConfig("StrictHostKeyChecking", "no");
    }
}
