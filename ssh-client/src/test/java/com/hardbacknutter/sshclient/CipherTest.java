package com.hardbacknutter.sshclient;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import javax.crypto.Cipher;

class CipherTest {

    private static final Logger LOGGER = new DbgJLogger();
    private static final SshClient SSH_CLIENT = new SshClient(LOGGER);

    @NonNull
    static Stream<Arguments> readArgs() {
        return Stream.of(
                Arguments.of("twofish-cbc"),
                Arguments.of("twofish256-cbc"),
                Arguments.of("twofish192-cbc"),
                Arguments.of("twofish128-cbc"),

                Arguments.of("twofish256-ctr"),
                Arguments.of("twofish192-ctr"),
                Arguments.of("twofish128-ctr"),

                Arguments.of("blowfish-cbc"),

                Arguments.of("cast128-cbc"),
                Arguments.of("cast128-ctr"),

                Arguments.of("seed-cbc@ssh.com"),

                Arguments.of("3des-cbc"),
                Arguments.of("3des-ctr"),

                Arguments.of("aes256-ctr"),
                Arguments.of("aes192-ctr"),
                Arguments.of("aes128-ctr"),

                Arguments.of("aes256-cbc"),
                Arguments.of("aes192-cbc"),
                Arguments.of("aes128-cbc"),

                Arguments.of("none")
        );
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void runSimpleCipher(@NonNull final String cipherName)
            throws java.security.GeneralSecurityException {
        final SshClientConfig config = SSH_CLIENT.getConfig();
        final SshCipher cipher = ImplementationFactory.getCipher(config, cipherName);

        final byte[] input = new byte[10000];
        final byte[] encoded = new byte[20000];
        final byte[] decoded = new byte[10000];

        final byte[] bytes = LongText.getBytes();
        System.arraycopy(bytes, 0, input, 0, bytes.length);

        cipher.init(Cipher.ENCRYPT_MODE, new byte[32], new byte[64]);
        cipher.update(input, 0, input.length, encoded, 0);

        cipher.init(Cipher.DECRYPT_MODE, new byte[32], new byte[64]);
        cipher.update(encoded, 0, input.length, decoded, 0);

        assertArrayEquals(input, decoded, cipher.toString());
    }
}
