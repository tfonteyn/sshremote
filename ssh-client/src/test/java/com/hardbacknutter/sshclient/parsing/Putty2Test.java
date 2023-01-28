package com.hardbacknutter.sshclient.parsing;

import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class Putty2Test
        extends BaseLoadTest {
    @Test
    void dsa_enc()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES + "putty2/dsa_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }

    @Test
    void rsa_enc()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES + "putty2/rsa_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }

    @Test
    void ecdsa256_enc()
            throws IOException, GeneralSecurityException {
        final SshKeyPair kp = parseFile(TEST_RESOURCES + "putty2/ecdsa256_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }
}
