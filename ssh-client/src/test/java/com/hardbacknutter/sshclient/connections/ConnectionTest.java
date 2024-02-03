package com.hardbacknutter.sshclient.connections;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.MyUserInfo;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test all combinations of {@link #SIG_ALGS} and {@link #KEX_ALGS}.
 */
public class ConnectionTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;

    private static final UserInfo ui = new MyUserInfo(Constants.PASSWORD, "qwerty");

    private String keyDir = System.getProperty("user.home") + File.separatorChar + ".ssh";

    @NonNull
    static Stream<Arguments> withAlgorithms() {
        final List<Arguments> list = new ArrayList<>();
        SIG_ALGS.forEach(sig -> KEX_ALGS.stream().map(kex -> Arguments.of(sig, kex))
                                        .forEach(list::add));
        return list.stream();
    }

    /**
     * Public keys used here must be added on the server in "~/.ssh/authorized_keys
     */
    @NonNull
    public static Stream<Arguments> withKeys() {
        return Stream.of(
                Arguments.of("id_rsa", null),
                Arguments.of("id_ecdsa", null),
                Arguments.of("id_rsa_qwerty", ui)
        );
    }

    @BeforeEach
    void setup()
            throws GeneralSecurityException, IOException {
        super.setup(ZIPPER[ZIP]);
    }

    @ParameterizedTest
    @MethodSource("withAlgorithms")
    void connectWithPassword(@NonNull final String hostKeyAlgorithms,
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

    @ParameterizedTest
    @MethodSource("withKeys")
    void connectWithPublicKey(@NonNull final String prvKeyFile,
                              @Nullable final UserInfo ui)
            throws SshException, GeneralSecurityException, IOException {

        sshClient.addIdentity(keyDir + File.separatorChar + prvKeyFile);

        final Session session = sshClient.getSession(Constants.USERNAME,
                                                     Constants.HOST, Constants.PORT);
        session.setUserInfo(ui);
        session.connect();
        session.disconnect();
    }
}
