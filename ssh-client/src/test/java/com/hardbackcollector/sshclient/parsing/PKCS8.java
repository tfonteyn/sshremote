package com.hardbackcollector.sshclient.parsing;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hardbackcollector.sshclient.keypair.SshKeyPair;
import com.hardbackcollector.sshclient.keypair.util.KeyPairTool;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;


class PKCS8
        extends BaseLoadTest {

    @Test
    void dsa()
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());

        final SshKeyPair kp = keyPairTool.load(
                new File(TEST_RESOURCES + "legacy/pkcs8_dsa.key").getAbsolutePath(),
                new File(TEST_RESOURCES + "legacy/pkcs8_dsa.crt").getAbsolutePath());
        assertNotNull(kp);
        signAndVerify(kp);
    }

    @Test
    void rsa()
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());

        final SshKeyPair kp = keyPairTool.load(
                new File(TEST_RESOURCES + "legacy/pkcs8_rsa.key").getAbsolutePath(),
                new File(TEST_RESOURCES + "legacy/pkcs8_rsa.crt").getAbsolutePath());
        assertNotNull(kp);
        signAndVerify(kp);
    }

    @Test
    void rsa_enc()
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());

        final SshKeyPair kp = keyPairTool.load(
                new File(TEST_RESOURCES + "legacy/pkcs8_rsa_qwerty.key").getAbsolutePath(),
                new File(TEST_RESOURCES + "legacy/pkcs8_rsa_qwerty.crt").getAbsolutePath());
        assertTrue(kp.decryptPrivateKey("qwerty".getBytes(StandardCharsets.UTF_8)),
                "Failed to decrypt");
        signAndVerify(kp);
    }

    /**
     * openssl ecparam -name secp256r1 -out secp256r1.param
     * openssl ecparam -in secp256r1.param -genkey -noout -out secp256r1
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp256r1 -out pkcs8_secp256r1.key
     * <p>
     * openssl ec -in secp256r1 -pubout -out secp256r1.pub
     */
    @Test
    void secp256k1()
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());

        final SshKeyPair kp = keyPairTool.load(
                new File(TEST_RESOURCES + "legacy/pkcs8_secp256r1.key").getAbsolutePath(),
                null);
        assertNotNull(kp);
        signAndVerify(kp);
    }

    /**
     * openssl ecparam -name secp384r1 -out secp384r1.param
     * openssl ecparam -in secp384r1.param -genkey -noout -out secp384r1
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp384r1 -out pkcs8_secp384r1.key
     * <p>
     * openssl ec -in secp384r1 -pubout -out secp384r1.pub
     */
    @Test
    void secp384k1()
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());

        final SshKeyPair kp = keyPairTool.load(
                new File(TEST_RESOURCES + "legacy/pkcs8_secp384r1.key").getAbsolutePath(),
                null);
        assertNotNull(kp);
        signAndVerify(kp);
    }

    /**
     * openssl ecparam -name secp521r1 -out secp521r1.param
     * openssl ecparam -in secp521r1.param -genkey -noout -out secp521r1
     * openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in secp521r1 -out pkcs8_secp521r1.key
     * <p>
     * openssl ec -in secp521r1 -pubout -out secp521r1.pub
     */
    @Test
    void secp521k1()
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());

        final SshKeyPair kp = keyPairTool.load(
                new File(TEST_RESOURCES + "legacy/pkcs8_secp521r1.key").getAbsolutePath(),
                null);
        assertNotNull(kp);
        signAndVerify(kp);
    }
}
