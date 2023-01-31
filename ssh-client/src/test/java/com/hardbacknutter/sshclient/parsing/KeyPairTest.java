package com.hardbacknutter.sshclient.parsing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.DbgJLogger;
import com.hardbacknutter.sshclient.LongText;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.util.KeyPairTool;
import com.hardbacknutter.sshclient.keypair.util.KeyPairWriter;
import com.hardbacknutter.sshclient.signature.SshSignature;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;


class KeyPairTest {

    private static final String TEST_RESOURCES = "src/test/resources/";
    private static final String PASSWORD = "qwerty";
    private static final String SSH_DSS = "ssh-dss";
    private static final String SSH_RSA = "ssh-rsa";
    private static final String ECDSA_SHA_2_NISTP_256 = "ecdsa-sha2-nistp256";
    private static final String ECDSA_SHA_2_NISTP_384 = "ecdsa-sha2-nistp384";
    private static final String ECDSA_SHA_2_NISTP_521 = "ecdsa-sha2-nistp521";
    private static final String SSH_ED_25519 = "ssh-ed25519";
    private static final String SSH_ED_448 = "ssh-ed448";

    private static final SshClient SSH_CLIENT = new SshClient(new DbgJLogger());

    @NonNull
    static Stream<Arguments> readArgs() {
        return Stream.of(
                /*
                  openssl dsaparam -out pkcs8_dsa.param 2048
                  openssl gendsa -out pkcs8_dsa.pem pkcs8_dsa.param
                  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs8_dsa.pem -out pkcs8_dsa.key
                  openssl dsa -in pkcs8_dsa.pem -outform PEM -pubout -out pkcs8_dsa.pub
                 */
                Arguments.of("openssl/pkcs8_dsa.key", "openssl/pkcs8_dsa.pub", null, SSH_DSS),
                /*
                  openssl genrsa -out pkcs8_rsa.pem 2048
                  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs8_rsa.pem -out pkcs8_rsa.key
                  openssl rsa -in pkcs8_rsa.pem -outform PEM -pubout -out pkcs8_rsa.pub
                 */
                Arguments.of("openssl/pkcs8_rsa.key", "openssl/pkcs8_rsa.pub", null, SSH_RSA),

                /*
                  openssl ecparam -name secp256r1 -out pkcs8_secp256r1.param
                  openssl ecparam -in pkcs8_secp256r1.param -genkey -noout -out pkcs8_secp256r1.pem
                  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs8_secp256r1.pem -out pkcs8_secp256r1.key
                  openssl ec -in pkcs8_secp256r1.pem -pubout -out pkcs8_secp256r1.pub
                 */
                Arguments.of("openssl/pkcs8_secp256r1.key",
                             "openssl/pkcs8_secp256r1.pub", null, ECDSA_SHA_2_NISTP_256),
                /*
                  openssl ecparam -name secp384r1 -out pkcs8_secp384r1.param
                  openssl ecparam -in pkcs8_secp384r1.param -genkey -noout -out pkcs8_secp384r1.pem
                  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs8_secp384r1.pem -out pkcs8_secp384r1.key
                  openssl ec -in pkcs8_secp384r1.pem -pubout -out pkcs8_secp384r1.pub
                 */
                Arguments.of("openssl/pkcs8_secp384r1.key",
                             "openssl/pkcs8_secp384r1.pub", null, ECDSA_SHA_2_NISTP_384),
                /*
                  openssl ecparam -name secp521r1 -out pkcs8_secp521r1.param
                  openssl ecparam -in pkcs8_secp521r1.param -genkey -noout -out pkcs8_secp521r1.pem
                  openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs8_secp521r1.pem -out pkcs8_secp521r1.key
                  openssl ec -in pkcs8_secp521r1.pem -pubout -out pkcs8_secp521r1.pub
                 */
                Arguments.of("openssl/pkcs8_secp521r1.key",
                             "openssl/pkcs8_secp521r1.pub", null, ECDSA_SHA_2_NISTP_521)
        );
    }

    @ParameterizedTest
    @MethodSource("readAndWriteArgs")
    void readAndWrite(@NonNull final String path,
                      @Nullable final String password,
                      @NonNull final String keyType)
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + path, null, password, keyType);
        write(kp, null);
        signAndVerify(kp);
    }

    @ParameterizedTest
    @MethodSource("readOnlyArgs")
    void readOnly(@NonNull final String path,
                  @Nullable final String password,
                  @NonNull final String keyType)
            throws IOException, GeneralSecurityException {

        final SshKeyPair kp = parseFile(TEST_RESOURCES + path, null, password, keyType);
        write(kp, null);
        signAndVerify(kp);
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void read(@NonNull final String prv,
              @Nullable final String pub,
              @Nullable final String password,
              @NonNull final String keyType)
            throws IOException, GeneralSecurityException {

        final String prvPath = new File(TEST_RESOURCES + prv).getAbsolutePath();
        final String pubPath = pub != null
                ? new File(TEST_RESOURCES + pub).getAbsolutePath()
                : null;

        final KeyPairTool keyPairTool = new KeyPairTool(SSH_CLIENT.getConfig());
        final SshKeyPair keyPair = keyPairTool.load(prvPath, pubPath);
        assertNotNull(keyPair);

        final byte[] pp = password != null ? password.getBytes(StandardCharsets.UTF_8) : null;

        assertTrue(keyPair.decryptPrivateKey(pp), "Failed to decrypt");

        final String hostKeyAlgorithm = keyPair.getHostKeyAlgorithm();
        assertEquals(keyType, hostKeyAlgorithm);

        writePubKey(keyPair);

        // sign the text-blob and verify
        final byte[] text = LongText.getBytes();
        final byte[] sig = keyPair.getSignature(text, hostKeyAlgorithm);
        final SshSignature verifier = keyPair.getVerifier();
        verifier.update(text);
        assertTrue(verifier.verify(sig));
    }

    void writePubKey(@NonNull final SshKeyPair keyPair)
            throws GeneralSecurityException {
        final KeyPairWriter keyPairWriter = new KeyPairWriter();

        try (final PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8)) {
            keyPairWriter.writePublicKey(keyPair, out, keyPair.getPublicKeyComment());
        }
    }
}
