package com.hardbacknutter.sshclient.parsing;

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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("LongLine")
class KeyPairTest {

    private static final SshClient SSH_CLIENT = SshClientFactory.create(new DbgJLogger());

    @NonNull
    static Stream<Arguments> readPutty() {
        return Stream.of(
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "putty3/dsa.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "putty3/dsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "putty3/rsa.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "putty3/rsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "putty3/ecdsa256.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "putty3/ecdsa256_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "putty3/ecdsa384.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "putty3/ecdsa384_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "putty3/ecdsa521.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "putty3/ecdsa521_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "putty3/ed25519.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "putty3/ed25519_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "putty3/ed448.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "putty3/ed448_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),

                Arguments.of(HostKeyAlgorithm.SSH_DSS, "putty2/dsa.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "putty2/dsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "putty2/rsa.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "putty2/rsa_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "putty2/ecdsa256.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "putty2/ecdsa256_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "putty2/ecdsa384.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "putty2/ecdsa384_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "putty2/ecdsa521.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "putty2/ecdsa521_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "putty2/ed25519.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "putty2/ed25519_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "putty2/ed448.ppk", null, null),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "putty2/ed448_enc.ppk", null, Constants.KEY_FILES_PASSPHRASE)
        );
    }

    @NonNull
    static Stream<Arguments> readLegacy() {
        return Stream.of(
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "legacy/dsa", "legacy/dsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "legacy/dsa", "legacy/dsa.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "legacy/dsa", "legacy/dsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "legacy/dsa_enc", "legacy/dsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "legacy/rsa", "legacy/rsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "legacy/rsa", "legacy/rsa.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "legacy/rsa_enc", "legacy/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "legacy/ecdsa256", "legacy/ecdsa256.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "legacy/ecdsa256", "legacy/ecdsa256.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "legacy/ecdsa256_enc", "legacy/ecdsa256_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "legacy/ecdsa384", "legacy/ecdsa384.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "legacy/ecdsa384", "legacy/ecdsa384.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "legacy/ecdsa384_enc", "legacy/ecdsa384_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "legacy/ecdsa521", "legacy/ecdsa521.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "legacy/ecdsa521", "legacy/ecdsa521.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "legacy/ecdsa521_enc", "legacy/ecdsa521_enc.pub", Constants.KEY_FILES_PASSPHRASE)
        );
    }

    @NonNull
    static Stream<Arguments> readOpensshV1() {
        return Stream.of(
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "opensshv1/dsa", "opensshv1/dsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "opensshv1/dsa", "opensshv1/dsa.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "opensshv1/dsa_enc", "opensshv1/dsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "opensshv1/rsa", "opensshv1/rsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "opensshv1/rsa", "opensshv1/rsa.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "opensshv1/rsa_enc", "opensshv1/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "opensshv1/ecdsa256", "opensshv1/ecdsa256.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "opensshv1/ecdsa256", "opensshv1/ecdsa256.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "opensshv1/ecdsa256_enc", "opensshv1/ecdsa256_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "opensshv1/ecdsa384", "opensshv1/ecdsa384.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "opensshv1/ecdsa384", "opensshv1/ecdsa384.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "opensshv1/ecdsa384_enc", "opensshv1/ecdsa384_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "opensshv1/ecdsa521", "opensshv1/ecdsa521.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "opensshv1/ecdsa521", "opensshv1/ecdsa521.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "opensshv1/ecdsa521_enc", "opensshv1/ecdsa521_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "opensshv1/ed25519", "opensshv1/ed25519.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "opensshv1/ed25519", "opensshv1/ed25519.pub_ssh2", null),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "opensshv1/ed25519_enc", "opensshv1/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE)
        );
    }

    @NonNull
    static Stream<Arguments> readOpenSsl_pem() {
        return Stream.of(
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa.pem", "openssl/dsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa_enc.pem", "openssl/dsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa.pem", "openssl/rsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa_enc.pem", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1.pem", "openssl/secp256r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1.pem", "openssl/secp384r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1.pem", "openssl/secp521r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1_enc.pem", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1_enc.pem", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1_enc.pem", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "openssl/ed25519.pem", "openssl/ed25519.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "openssl/ed25519_enc.pem", "openssl/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "openssl/ed448.pem", "openssl/ed448.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "openssl/ed448_enc.pem", "openssl/ed448_enc.pub", Constants.KEY_FILES_PASSPHRASE)
        );
    }

    @NonNull
    static Stream<Arguments> readOpenSsl_dss() {
        return Stream.of(
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa.pkcs8", "openssl/dsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa_enc.pkcs8", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa_enc.pkcs8_traditional", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa_scrypt.pkcs8", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_DSS, "openssl/dsa_scrypt.pkcs8_traditional", "openssl/dsa.pub", Constants.KEY_FILES_PASSPHRASE)
                );
    }

    @NonNull
    static Stream<Arguments> readOpenSsl_rsa() {
        return Stream.of(
                //Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa.pkcs8", "openssl/rsa.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa_enc.pkcs8", "openssl/rsa_enc.pub",  Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa_enc.pkcs8_traditional", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa_scrypt.pkcs8", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_RSA, "openssl/rsa_scrypt.pkcs8_traditional", "openssl/rsa_enc.pub", Constants.KEY_FILES_PASSPHRASE)
                );
    }

    @NonNull
    static Stream<Arguments> readOpenSsl_ecdsa() {
        return Stream.of(

                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1.pkcs8", "openssl/secp256r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1.pkcs8", "openssl/secp384r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1.pkcs8", "openssl/secp521r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1.pkcs8_traditional", "openssl/secp256r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1.pkcs8_traditional", "openssl/secp384r1.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1.pkcs8_traditional", "openssl/secp521r1.pub", null),


                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1_enc.pkcs8", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1_enc.pkcs8", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1_enc.pkcs8", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1_scrypt.pkcs8", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1_scrypt.pkcs8", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1_scrypt.pkcs8", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE),

                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1_enc.pkcs8_traditional", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1_enc.pkcs8_traditional", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1_enc.pkcs8_traditional", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256, "openssl/secp256r1_scrypt.pkcs8_traditional", "openssl/secp256r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384, "openssl/secp384r1_scrypt.pkcs8_traditional", "openssl/secp384r1.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521, "openssl/secp521r1_scrypt.pkcs8_traditional", "openssl/secp521r1.pub", Constants.KEY_FILES_PASSPHRASE)
                );
    }

    @NonNull
    static Stream<Arguments> readOpenSsl_ed() {
        return Stream.of(
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "openssl/ed25519.pkcs8", "openssl/ed25519.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "openssl/ed25519_enc.pkcs8", "openssl/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED25519, "openssl/ed25519_scrypt.pkcs8", "openssl/ed25519_enc.pub", Constants.KEY_FILES_PASSPHRASE),

                Arguments.of(HostKeyAlgorithm.SSH_ED448, "openssl/ed448.pkcs8", "openssl/ed448.pub", null),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "openssl/ed448_enc.pkcs8", "openssl/ed448_enc.pub", Constants.KEY_FILES_PASSPHRASE),
                Arguments.of(HostKeyAlgorithm.SSH_ED448, "openssl/ed448_scrypt.pkcs8", "openssl/ed448_enc.pub", Constants.KEY_FILES_PASSPHRASE)
        );
    }

    @ParameterizedTest
    @MethodSource({
            "readPutty",
            "readLegacy",
            "readOpensshV1",
            "readOpenSsl_pem",
            "readOpenSsl_dss",
            "readOpenSsl_ed",
            "readOpenSsl_rsa",
            "readOpenSsl_ecdsa"
    })
    void read(@NonNull final String keyType,
              @NonNull final String prv,
              @Nullable final String pub,
              @Nullable final String password)
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
