package com.hardbacknutter.sshclient.connections;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

/**
 * Uses a fixed signature algorithm, and variable KEX algorithms.
 */
class HostKeyTest
        extends BaseConnectionTest {

    private static final boolean TEST_REKEY = false;

    private static final int ZIP = 1;

    @BeforeEach
    void setup()
            throws GeneralSecurityException, IOException {
        super.setup(ZIPPER[ZIP]);
    }

    @NonNull
    static Stream<Arguments> readArgs() {
        //TODO: automate this
        final int kex = 0;

        return Stream.of(
                Arguments.of(kexAlg[kex], Constants.SSH_RSA),
                Arguments.of(kexAlg[kex], Constants.RSA_SHA_2_256),
                Arguments.of(kexAlg[kex], Constants.RSA_SHA_2_512),
                Arguments.of(kexAlg[kex], Constants.ECDSA_SHA_2_NISTP_256),
                //Arguments.of(kexAlg[kex], Constants.ECDSA_SHA_2_NISTP_384),
                //Arguments.of(kexAlg[kex], Constants.ECDSA_SHA_2_NISTP_521),
                Arguments.of(kexAlg[kex], Constants.SSH_ED_25519)
        );
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void connect(@NonNull final String kexAlgorithms,
                 @NonNull final String hostKeyAlgorithms)
            throws SshException, GeneralSecurityException, IOException, InterruptedException {

        final Session session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);

        session.setConfig(HostConfig.KEX_ALGS, kexAlgorithms);
        session.setConfig(HostConfig.HOST_KEY_ALGS, hostKeyAlgorithms);

        session.connect();
        if (TEST_REKEY) {
            Thread.sleep(100);
            session.rekey();
            Thread.sleep(5000);
        }
        session.disconnect();
    }
}
