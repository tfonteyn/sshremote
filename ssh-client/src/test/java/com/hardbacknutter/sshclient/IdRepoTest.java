package com.hardbacknutter.sshclient;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.util.KeyPairParser;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

class IdRepoTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
    }

    @NonNull
    static Stream<Arguments> readArgs() {
        return Stream.of(
                Arguments.of("legacy/rsa", false, "name"),
                Arguments.of("legacy/rsa_enc", true, "name.enc")
        );
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void repo(@NonNull final String prvKeyFile,
              final boolean encrypted,
              @NonNull final String name)
            throws GeneralSecurityException, IOException {

        final KeyPairParser keyPairParser = new KeyPairParser(sshClient.getConfig());
        final SshKeyPair keyPair = keyPairParser.parse(Constants.RESOURCES + prvKeyFile);

        final IdentityRepository identityRepository = sshClient.getIdentityRepository();

        final Identity identity = keyPair.toIdentity(name);

        identityRepository.add(identity);

        if (encrypted) {
            assertTrue(identity.decrypt(Constants.KEY_FILES_PASSPHRASE
                                                .getBytes(StandardCharsets.UTF_8)));
        }
        identityRepository.getIdentities().forEach(i -> {
            System.out.println(i.getName());
            assertFalse(i.isEncrypted());
        });
    }
}
