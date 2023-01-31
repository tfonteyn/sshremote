package com.hardbacknutter.sshclient;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.util.KeyPairTool;

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
        final SshKeyPair p1 = keyPairTool.load(Constants.RESOURCES + "legacy/rsa",
                                               Constants.RESOURCES + "legacy/rsa.pub");
        final SshKeyPair p2 = keyPairTool.load(Constants.RESOURCES + "legacy/rsa_enc",
                                               Constants.RESOURCES + "legacy/rsa_enc.pub");

        final IdentityRepository identityRepository = sshClient.getIdentityRepository();

        final Identity id1 = p1.toIdentity("name 1");
        final Identity id2 = p2.toIdentity("name 2");

        identityRepository.add(id1);
        identityRepository.add(id2);

        assertTrue(id1.decrypt(null));
        assertTrue(id2.decrypt(Constants.PASSWORD.getBytes(StandardCharsets.UTF_8)));

        identityRepository.getIdentities().forEach(identity -> {
            System.out.println(identity.getName());
            assertFalse(identity.isEncrypted());
        });
    }
}
