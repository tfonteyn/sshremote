package com.hardbacknutter.sshclient.parsing;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientFactory;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.util.KeyPairParser;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;


class KeyPairTest {

    private static final SshClient SSH_CLIENT = SshClientFactory.create(new DbgJLogger());

    @SuppressWarnings("LongLine")
    @NonNull
    static Stream<Arguments> readArgs() {

        return Stream.of(
                Arguments.of("putty3/dsa.ppk", null, null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("putty3/dsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("putty3/rsa.ppk", null, null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("putty3/rsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("putty3/ecdsa256.ppk", null, null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("putty3/ecdsa256_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("putty3/ecdsa384.ppk", null, null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("putty3/ecdsa384_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("putty3/ecdsa521.ppk", null, null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("putty3/ecdsa521_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("putty3/ed25519.ppk", null, null, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("putty3/ed25519_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("putty3/ed448.ppk", null, null, HostKeyAlgorithm.SSH_ED448),
                Arguments.of("putty3/ed448_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED448),


                Arguments.of("putty2/dsa.ppk", null, null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("putty2/dsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("putty2/rsa.ppk", null, null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("putty2/rsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("putty2/ecdsa256.ppk", null, null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("putty2/ecdsa256_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("putty2/ecdsa384.ppk", null, null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("putty2/ecdsa384_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("putty2/ecdsa521.ppk", null, null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("putty2/ecdsa521_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("putty2/ed25519.ppk", null, null, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("putty2/ed25519_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("putty2/ed448.ppk", null, null, HostKeyAlgorithm.SSH_ED448),
                Arguments.of("putty2/ed448_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED448),


                Arguments.of("legacy/dsa", "legacy/dsa.pub", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("legacy/dsa", "legacy/dsa.pub_ssh2", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("legacy/dsa", "legacy/dsa.pub", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("legacy/dsa_enc", "legacy/dsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("legacy/rsa", "legacy/rsa.pub", null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("legacy/rsa", "legacy/rsa.pub_ssh2", null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("legacy/rsa_enc", "legacy/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("legacy/ecdsa256", "legacy/ecdsa256.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("legacy/ecdsa256", "legacy/ecdsa256.pub_ssh2", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("legacy/ecdsa256_enc", "legacy/ecdsa256_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("legacy/ecdsa384", "legacy/ecdsa384.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("legacy/ecdsa384", "legacy/ecdsa384.pub_ssh2", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("legacy/ecdsa384_enc", "legacy/ecdsa384_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("legacy/ecdsa521", "legacy/ecdsa521.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("legacy/ecdsa521", "legacy/ecdsa521.pub_ssh2", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("legacy/ecdsa521_enc", "legacy/ecdsa521_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),


                Arguments.of("opensshv1/dsa", "opensshv1/dsa.pub", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("opensshv1/dsa", "opensshv1/dsa.pub_ssh2", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("opensshv1/dsa_enc", "opensshv1/dsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("opensshv1/rsa", "opensshv1/rsa.pub", null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("opensshv1/rsa", "opensshv1/rsa.pub_ssh2", null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("opensshv1/rsa_enc", "opensshv1/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("opensshv1/ecdsa256", "opensshv1/ecdsa256.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("opensshv1/ecdsa256", "opensshv1/ecdsa256.pub_ssh2", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("opensshv1/ecdsa256_enc", "opensshv1/ecdsa256_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("opensshv1/ecdsa384", "opensshv1/ecdsa384.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("opensshv1/ecdsa384", "opensshv1/ecdsa384.pub_ssh2", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("opensshv1/ecdsa384_enc", "opensshv1/ecdsa384_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("opensshv1/ecdsa521", "opensshv1/ecdsa521.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("opensshv1/ecdsa521", "opensshv1/ecdsa521.pub_ssh2", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("opensshv1/ecdsa521_enc", "opensshv1/ecdsa521_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),


                Arguments.of("openssl/dsa.pem", "openssl/dsa.pub", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("openssl/dsa_enc.pem", "openssl/dsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("openssl/rsa.pem", "openssl/rsa.pub", null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("openssl/rsa_enc.pem", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("openssl/secp256r1.pem", "openssl/secp256r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1.pem", "openssl/secp384r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1.pem", "openssl/secp521r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("openssl/secp256r1_enc.pem", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1_enc.pem", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1_enc.pem", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("openssl/ed25519.pem", "openssl/ed25519.pub", null, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("openssl/ed25519_enc.pem", "openssl/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("openssl/ed448.pem", "openssl/ed448.pub", null, HostKeyAlgorithm.SSH_ED448),
                Arguments.of("openssl/ed448_enc.pem", "openssl/ed448_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED448),


                Arguments.of("openssl/dsa.pkcs8", "openssl/dsa.pub", null, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("openssl/dsa_enc.pkcs8", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("openssl/dsa_enc.pkcs8_traditional", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("openssl/dsa_scrypt.pkcs8", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),
                Arguments.of("openssl/dsa_scrypt.pkcs8_traditional", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_DSS),


                Arguments.of("openssl/rsa.pkcs8", "openssl/rsa.pub", null, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("openssl/rsa_enc.pkcs8", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("openssl/rsa_enc.pkcs8_traditional", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("openssl/rsa_scrypt.pkcs8", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),
                Arguments.of("openssl/rsa_scrypt.pkcs8_traditional", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_RSA),


                Arguments.of("openssl/secp256r1.pkcs8", "openssl/secp256r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1.pkcs8", "openssl/secp384r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1.pkcs8", "openssl/secp521r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("openssl/secp256r1.pkcs8_traditional", "openssl/secp256r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1.pkcs8_traditional", "openssl/secp384r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1.pkcs8_traditional", "openssl/secp521r1.pub", null, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),


                Arguments.of("openssl/secp256r1_enc.pkcs8", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1_enc.pkcs8", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1_enc.pkcs8", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("openssl/secp256r1_scrypt.pkcs8", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1_scrypt.pkcs8", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1_scrypt.pkcs8", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),

                Arguments.of("openssl/secp256r1_enc.pkcs8_traditional", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1_enc.pkcs8_traditional", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1_enc.pkcs8_traditional", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),
                Arguments.of("openssl/secp256r1_scrypt.pkcs8_traditional", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256),
                Arguments.of("openssl/secp384r1_scrypt.pkcs8_traditional", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384),
                Arguments.of("openssl/secp521r1_scrypt.pkcs8_traditional", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521),


                Arguments.of("openssl/ed25519.pkcs8", "openssl/ed25519.pub", null, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("openssl/ed25519_enc.pkcs8", "openssl/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED25519),
                Arguments.of("openssl/ed25519_scrypt.pkcs8", "openssl/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED25519),

                Arguments.of("openssl/ed448.pkcs8", "openssl/ed448.pub", null, HostKeyAlgorithm.SSH_ED448),
                Arguments.of("openssl/ed448_enc.pkcs8", "openssl/ed448_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED448),
                Arguments.of("openssl/ed448_scrypt.pkcs8", "openssl/ed448_enc.pub", Constants.KEY_FILES_PASSPHRASE, HostKeyAlgorithm.SSH_ED448)
        );
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void read(@NonNull final String prv,
              @Nullable final String pub,
              @Nullable final String password,
              @NonNull final String keyType)
            throws IOException, GeneralSecurityException {

        final String prvPath = new File(Constants.RESOURCES + prv).getAbsolutePath();
        final String pubPath = pub != null
                ? new File(Constants.RESOURCES + pub).getAbsolutePath()
                : null;

        final KeyPairParser keyPairParser = new KeyPairParser(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairParser.parse(prvPath, pubPath);
        assertNotNull(keyPair);

        final byte[] pp = password != null ? password.getBytes(StandardCharsets.UTF_8) : null;

        assertTrue(keyPair.decrypt(pp), "Failed to decrypt");

        final String hostKeyAlgorithm = keyPair.getHostKeyAlgorithm();
        assertEquals(keyType, hostKeyAlgorithm);

        if (pubPath != null) {
            final File fp = new File(pubPath + ".fp_sha256");
            if (fp.exists()) {
                final String expected = Files.readString(fp.toPath()).strip();
                assertEquals(expected, keyPair.getFingerPrint("SHA-256"));
            }
        }
    }
}
