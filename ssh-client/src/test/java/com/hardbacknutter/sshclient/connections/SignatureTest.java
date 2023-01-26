package com.hardbacknutter.sshclient.connections;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Uses a fixed KEX algorithm, and variable signature algorithms.
 * <p>
 * 2022-01-26: current test server supports these sig algorithms:
 * <pre>
 * curve25519-sha256,
 * curve25519-sha256@libssh.org,
 * ecdh-sha2-nistp256,
 * ecdh-sha2-nistp384,
 * ecdh-sha2-nistp521,
 * diffie-hellman-group-exchange-sha256,
 * diffie-hellman-group16-sha512,
 * diffie-hellman-group18-sha512,
 * diffie-hellman-group14-sha256
 * </pre>
 */
class SignatureTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;
    private Session session;

    @BeforeEach
    void setup()
            throws GeneralSecurityException, IOException {
        super.setup(ZIPPER[ZIP]);
        //TODO: use a junit parameter test and run all in one go.

        sshClient.setConfig(HostConfig.HOST_KEY_ALGS, sigAlg[4]);
    }

    @Test
    void ecdh256()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "ecdh-sha2-nistp256");

        session.connect();
        session.disconnect();
    }

    @Test
    void ecdh384()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "ecdh-sha2-nistp384");

        session.connect();
        session.disconnect();
    }

    @Test
    void ecdh521()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "ecdh-sha2-nistp521");

        session.connect();
        session.disconnect();
    }

    @Test
    void curve25519()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "curve25519-sha256");

        session.connect();
        session.disconnect();
    }

    @Test
    void curve25519libssh()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "curve25519-sha256@libssh.org");

        session.connect();
        session.disconnect();
    }

    @Test
    void dhGroupEx()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "diffie-hellman-group-exchange-sha256");

        session.connect();
        session.disconnect();
    }

    @Test
    void dhGroup16()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "diffie-hellman-group16-sha512");

        session.connect();
        session.disconnect();
    }

    @Test
    void dhGroup18x()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "diffie-hellman-group18-sha512");

        session.connect();
        session.disconnect();
    }

    @Test
    void dhGroup14()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.KEX_ALGS, "diffie-hellman-group14-sha256");

        session.connect();
        session.disconnect();
    }
}
