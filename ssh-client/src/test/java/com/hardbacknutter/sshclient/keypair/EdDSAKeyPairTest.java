package com.hardbacknutter.sshclient.keypair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class EdDSAKeyPairTest
        extends BaseKeyPairTest {

    @Test
    void edKeyPairTest()
            throws GeneralSecurityException, IOException {

        keyPairTest("ed25519");
        keyPairTest("ed448");
    }
}
