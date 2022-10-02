package com.hardbacknutter.sshclient.parsing;

import com.hardbacknutter.sshclient.keypair.SshKeyPair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class PuTTY
        extends BaseLoadTest {

    @Test
    void dsa()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        // PPK-3 not encrypted
        kp = parseFile(TEST_RESOURCES + "putty/dsa.ppk", null);
        signAndVerify(kp);

        // PPK-2 encrypted
        kp = parseFile(TEST_RESOURCES + "putty/dsa2_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }

    @Test
    void rsa()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        // PPK-3 not encrypted
        kp = parseFile(TEST_RESOURCES + "putty/rsa.ppk", null);
        signAndVerify(kp);

        // PPK-2 encrypted
        kp = parseFile(TEST_RESOURCES + "putty/rsa2_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }


    // This test will fail... we don't have support for ECDSA keys from PuTTY yet
    // @Test
    void ecdsa()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        // PPK-3 not encrypted
        kp = parseFile(TEST_RESOURCES + "putty/ecdsa256.ppk", null);
        signAndVerify(kp);

        // PPK-2 encrypted
        kp = parseFile(TEST_RESOURCES + "putty/dsa2_qwerty.ppk", "qwerty");
        signAndVerify(kp);
    }
}
