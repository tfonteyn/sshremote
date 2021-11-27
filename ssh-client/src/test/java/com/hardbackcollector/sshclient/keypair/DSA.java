package com.hardbackcollector.sshclient.keypair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class DSA
        extends BaseKeyPairTest {

    @Test
    void dsaKeyPairTest()
            throws GeneralSecurityException, IOException {

        keyPairTest("dsa", 1024);
        keyPairTest("dsa", 2048);
    }

}
