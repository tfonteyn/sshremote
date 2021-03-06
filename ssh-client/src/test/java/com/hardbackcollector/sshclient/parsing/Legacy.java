package com.hardbackcollector.sshclient.parsing;

import com.hardbackcollector.sshclient.keypair.SshKeyPair;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;


class Legacy
        extends BaseLoadTest {

    @Test
    void dsa()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "legacy/dsa", null);
        write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void dsa_enc()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "legacy/dsa_qwerty", "qwerty");
        write(kp, "qwerty");
        signAndVerify(kp);
    }

    @Test
    void rsa()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "legacy/rsa", null);
        write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void rsa_enc()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "legacy/rsa_qwerty", "qwerty");
        write(kp, "qwerty");
        signAndVerify(kp);
    }

    @Test
    void ecdsa()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        kp = parseFile(TEST_RESOURCES + "legacy/ecdsa256", null);
        write(kp, null);
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "legacy/ecdsa384", null);
        write(kp, null);
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "legacy/ecdsa521", null);
        write(kp, null);
        signAndVerify(kp);
    }

    @Test
    void ecdsa_enc()
            throws IOException, GeneralSecurityException {

        SshKeyPair kp;

        kp = parseFile(TEST_RESOURCES + "legacy/ecdsa256_qwerty", "qwerty");
        write(kp, "qwerty");
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "legacy/ecdsa384_qwerty", "qwerty");
        write(kp, "qwerty");
        signAndVerify(kp);

        kp = parseFile(TEST_RESOURCES + "legacy/ecdsa521_qwerty", "qwerty");
        write(kp, "qwerty");
        signAndVerify(kp);
    }

    /**
     * Just a sanity check. - same as {@link #ecdsa()} but generated by:
     * <p>
     * openssl ecparam -name secp256r1 -out secp256r1.param
     * openssl ecparam -in .\secp256r1.param -genkey -noout -out .\secp256r1
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in .\secp256r1 -out pkcs8_secp256r1.key
     * <p>
     * openssl ec -in secp256r1 -pubout -out secp256r1.pub
     */
    @Test
    void secp256k1()
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + "legacy/secp256r1", null);
        write(kp, null);
        signAndVerify(kp);
    }
}
