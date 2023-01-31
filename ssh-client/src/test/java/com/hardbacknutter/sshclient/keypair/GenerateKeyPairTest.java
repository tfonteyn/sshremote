package com.hardbacknutter.sshclient.keypair;

import static org.junit.jupiter.api.Assertions.assertTrue;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.keypair.util.KeyPairTool;
import com.hardbacknutter.sshclient.signature.SshSignature;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

class GenerateKeyPairTest {

    private static final Logger LOGGER = new DbgJLogger();
    private static final SshClient SSH_CLIENT = new SshClient(LOGGER);

    @NonNull
    static Stream<Arguments> readArgs() {
        return Stream.of(
                Arguments.of("dsa", 1024),
                Arguments.of("dsa", 2048),

                Arguments.of("rsa", 1024),
                Arguments.of("rsa", 2048),
                Arguments.of("rsa", 4096),
                // 8192 is SLOW...
                // Arguments.of("rsa", 8192),

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
        final byte[] text = Constants.getTextBytes();

        final KeyPairTool keyPairGen = new KeyPairTool(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairGen.generateKeyPair(keyType, keySize);

        final String hostKeyAlgorithm = keyPair.getHostKeyAlgorithm();
        final byte[] sig = keyPair.getSignature(text, hostKeyAlgorithm);

        final SshSignature verifier = keyPair.getVerifier();
        verifier.update(text);

        assertTrue(verifier.verify(sig));
    }
}
