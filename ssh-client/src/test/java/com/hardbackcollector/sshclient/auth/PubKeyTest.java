package com.hardbackcollector.sshclient.auth;

import com.hardbackcollector.sshclient.MyUserInfo;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.connections.BaseConnectionTest;
import com.hardbackcollector.sshclient.userauth.UserInfo;
import com.hardbackcollector.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

class PubKeyTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;

    private Session session;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
    }

    @Test
    void id_rsa()
            throws SshException, GeneralSecurityException, IOException {
        final String keyFile = System.getProperty("user.home") + File.separatorChar
                + ".ssh" + File.separatorChar + "id_rsa";

        sshClient.addIdentity(keyFile);

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.connect();
        session.disconnect();
    }

    @Test
    void id_rsa_qwerty()
            throws SshException, GeneralSecurityException, IOException {
        final String keyFile = System.getProperty("user.home") + File.separatorChar
                + ".ssh" + File.separatorChar + "id_rsa_qwerty";

        sshClient.addIdentity(keyFile);

        final UserInfo ui = new MyUserInfo();

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setUserInfo(ui);
        session.connect();
        session.disconnect();
    }

    @Test
    void id_ecdsa()
            throws SshException, GeneralSecurityException, IOException {
        final String keyFile = System.getProperty("user.home") + File.separatorChar
                + ".ssh" + File.separatorChar + "id_ecdsa";

        sshClient.addIdentity(keyFile);

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.connect();
        session.disconnect();
    }
}
