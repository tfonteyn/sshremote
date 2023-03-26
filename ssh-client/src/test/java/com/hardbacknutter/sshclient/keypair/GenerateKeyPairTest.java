package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.LongText;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientFactory;
import com.hardbacknutter.sshclient.keypair.util.KeyPairGen;
import com.hardbacknutter.sshclient.signature.SshSignature;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertTrue;

class GenerateKeyPairTest {

    private static final Logger LOGGER = new DbgJLogger();
    private static final SshClient SSH_CLIENT = SshClientFactory.create(LOGGER);

    @NonNull
    static Stream<Arguments> readArgs() {
        return Stream.of(
                Arguments.of("dsa", 0),

                Arguments.of("rsa", 1024),
                Arguments.of("rsa", 2048),
                Arguments.of("rsa", 4096),

                Arguments.of("ecdsa", 256),
                Arguments.of("ecdsa", 384),
                Arguments.of("ecdsa", 521),

                Arguments.of("ed25519", 0),
                Arguments.of("ed448", 0)
        );
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void keyPairTest(@NonNull final String keyType,
                     final int keySize)
            throws GeneralSecurityException, IOException {

        final KeyPairGen keyPairGen = new KeyPairGen(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairGen.generateKeyPair(keyType, keySize);

        // sign the text-blob and verify
        final byte[] text = LongText.getBytes();
        final byte[] sig = keyPair.getSignature(text);
        final SshSignature verifier = keyPair.getVerifier();
        verifier.update(text);
        assertTrue(verifier.verify(sig));
    }
}
