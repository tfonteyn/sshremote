package com.hardbackcollector.sshclient.keypair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class RSA
        extends BaseKeyPairTest {

    @Test
    void rsaKeyPairTest()
            throws GeneralSecurityException, IOException {

        keyPairTest("rsa", 1024);
        // keyPairTest("rsa", 2048);
        // keyPairTest("rsa", 4096);
        // 8192 is SLOW...
        //keyPairTest("rsa", 8192);
    }
}
