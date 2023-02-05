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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Test all combinations of {@link #SIG_ALGS} and {@link #KEX_ALGS}.
 */
class ConnectionTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;

    @NonNull
    static Stream<Arguments> readArgs() {
        final List<Arguments> list = new ArrayList<>();
        SIG_ALGS.forEach(sig -> KEX_ALGS.stream().map(kex -> Arguments.of(sig, kex))
                                        .forEach(list::add));
        return list.stream();
    }

    @BeforeEach
    void setup()
            throws GeneralSecurityException, IOException {
        super.setup(ZIPPER[ZIP]);
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void connect(@NonNull final String hostKeyAlgorithms,
                 @NonNull final String kexAlgorithms)
            throws SshException, GeneralSecurityException, IOException {

        final Session session = sshClient.getSession(Constants.USERNAME,
                                                     Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, hostKeyAlgorithms);
        session.setConfig(HostConfig.KEX_ALGS, kexAlgorithms);

        session.connect();
        session.disconnect();
    }
}
