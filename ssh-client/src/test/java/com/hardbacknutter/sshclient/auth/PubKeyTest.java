package com.hardbacknutter.sshclient.auth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.MyUserInfo;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

/**
 * Public keys used here must be added on the server in "~/.ssh/authorized_keys
 */
class PubKeyTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;

    private static final UserInfo ui = new MyUserInfo(Constants.PASSWORD, "qwerty");

    private String keyDir;

    @NonNull
    static Stream<Arguments> readArgs() {
        return Stream.of(
                Arguments.of("id_rsa", null),
                Arguments.of("id_ecdsa", null),
                Arguments.of("id_rsa_qwerty", ui)
        );
    }

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);

        keyDir = System.getProperty("user.home") + File.separatorChar + ".ssh";
    }

    @ParameterizedTest
    @MethodSource("readArgs")
    void connect(@NonNull final String prvKeyFile,
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
