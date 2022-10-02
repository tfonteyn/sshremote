package com.hardbacknutter.sshclient.connections;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Uses a fixed signature algorithm, and variable KEX algorithms.
 * <p>
 * 2021-08-01: current test server supports these sig algorithms:
 * <p>
 * curve25519-sha256,
 * curve25519-sha256@libssh.org,
 * ecdh-sha2-nistp256,
 * ecdh-sha2-nistp384,
 * ecdh-sha2-nistp521,
 * diffie-hellman-group-exchange-sha256,
 * diffie-hellman-group16-sha512,
 * diffie-hellman-group18-sha512,
 * diffie-hellman-group14-sha256,
 * diffie-hellman-group14-sha1
 */
class HostKeyTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;
    private Session session;

    @BeforeEach
    void setup()
            throws GeneralSecurityException, IOException {
        super.setup(ZIPPER[ZIP]);

        //TODO: use a junit parameter test and run all in one go.
        sshClient.setConfig(HostConfig.KEX_ALGS, kexAlg[0]);
    }

    @Test
    void rsa1_rekey()
            throws SshException, GeneralSecurityException, IOException, InterruptedException {


        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, "ssh-rsa");

        session.connect();
        Thread.sleep(100);
        session.rekey();
        Thread.sleep(5000);
        session.disconnect();
    }

    @Test
    void rsa1()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, "ssh-rsa");

        session.connect();
        session.disconnect();
    }

    @Test
    void rsa256()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, "rsa-sha2-256");

        session.connect();
        session.disconnect();
    }

    @Test
    void rsa512()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, "rsa-sha2-512");

        session.connect();
        session.disconnect();
    }

    @Test
    void ecdsa256()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, "ecdsa-sha2-nistp256");

        session.connect();
        session.disconnect();
    }

    @Test
    void ed25519()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.setConfig(HostConfig.HOST_KEY_ALGS, "ssh-ed25519");

        session.connect();
        session.disconnect();
    }
}
