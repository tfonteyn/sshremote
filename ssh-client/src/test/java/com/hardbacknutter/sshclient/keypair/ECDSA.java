package com.hardbacknutter.sshclient.keypair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class ECDSA
        extends BaseKeyPairTest {

    @Test
    void ecdsaKeyPairTest()
            throws GeneralSecurityException, IOException {

        keyPairTest("ecdsa", 256);
        keyPairTest("ecdsa", 384);
        keyPairTest("ecdsa", 521);
    }
}
