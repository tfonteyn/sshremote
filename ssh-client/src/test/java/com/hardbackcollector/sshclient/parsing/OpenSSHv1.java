package com.hardbackcollector.sshclient.parsing;

import com.hardbackcollector.sshclient.keypair.SshKeyPair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class OpenSSHv1
        extends BaseLoadTest {

    @Test
    void rsa()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "id_rsa", null);
        write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void rsa_enc()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "id_rsa_qwerty", "qwerty");
        // OpenSSHv1 encrypted export not supported
        // write(kp, "qwerty");
        signAndVerify(kp);
    }

    @Test
    void dsa()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "id_dsa", null);
        write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void dsa_enc()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "id_dsa_qwerty", "qwerty");
        // OpenSSHv1 encrypted export not supported
        // write(kp, "qwerty");
        signAndVerify(kp);
    }

    @Test
    void ecdsa()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        kp = parseFile(TEST_RESOURCES + "id_ecdsa_256", null);
        write(kp, null);
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "id_ecdsa_384", null);
        write(kp, null);
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "id_ecdsa_521", null);
        write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void ecdsa_enc()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        kp = parseFile(TEST_RESOURCES + "id_ecdsa_256_qwerty", "qwerty");
        // OpenSSHv1 encrypted export not supported
        // write(kp, "qwerty");
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "id_ecdsa_384_qwerty", "qwerty");
        // OpenSSHv1 encrypted export not supported
        // write(kp, "qwerty");
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "id_ecdsa_521_qwerty", "qwerty");
        // OpenSSHv1 encrypted export not supported
        // write(kp, "qwerty");
        signAndVerify(kp);
    }

    @Test
    void ed25519()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "id_ed25519", null);
        // OpenSSHv1 ed25519 export not supported
        // write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void ed25519_enc()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "id_ed25519_qwerty", "qwerty");
        // OpenSSHv1 encrypted export not supported
        // write(kp, "qwerty");
        signAndVerify(kp);
    }
}
