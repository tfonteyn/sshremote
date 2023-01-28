package com.hardbacknutter.sshclient.parsing;

import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class Putty3Test
        extends BaseLoadTest {

    @Test
    void dsa()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES
                                                + "putty3/dsa.ppk", null);
        signAndVerify(kp);
    }

    @Test
    void dsa_enc()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES
                                                + "putty3/dsa_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }

    @Test
    void rsa()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES
                                                + "putty3/rsa.ppk", null);
        signAndVerify(kp);
    }

    @Test
    void rsa_enc()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES
                                                + "putty3/rsa_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }

    @Test
    void ecdsa()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES
                                                + "putty3/ecdsa256.ppk", null);
        signAndVerify(kp);
    }

    @Test
    void ecdsa_enc()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES
                                                + "putty3/ecdsa256_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }
}
