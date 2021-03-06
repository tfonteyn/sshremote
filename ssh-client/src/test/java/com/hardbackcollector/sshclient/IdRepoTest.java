package com.hardbackcollector.sshclient;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hardbackcollector.sshclient.connections.BaseConnectionTest;
import com.hardbackcollector.sshclient.identity.Identity;
import com.hardbackcollector.sshclient.identity.IdentityRepository;
import com.hardbackcollector.sshclient.keypair.SshKeyPair;
import com.hardbackcollector.sshclient.keypair.util.KeyPairTool;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class IdRepoTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
    }

    @Test
    void repo()
            throws GeneralSecurityException, IOException {

        final KeyPairTool keyPairTool = new KeyPairTool(sshClient.getConfig());
        final SshKeyPair p1 = keyPairTool.load(TEST_RESOURCES + "legacy/rsa");
        final SshKeyPair p2 = keyPairTool.load(TEST_RESOURCES + "legacy/rsa_qwerty");

        final IdentityRepository identityRepository = sshClient.getIdentityRepository();

        final Identity id1 = p1.toIdentity("name 1");
        final Identity id2 = p2.toIdentity("name 2");

        identityRepository.add(id1);
        identityRepository.add(id2);

        assertTrue(id1.decrypt(null));
        assertTrue(id2.decrypt("qwerty".getBytes(StandardCharsets.UTF_8)));

        identityRepository.getIdentities().forEach(identity -> {
            System.out.println(identity.getName());
            assertFalse(identity.isEncrypted());
        });
    }
}
