package com.hardbacknutter.sshclient.channels.exec;

import com.hardbacknutter.sshclient.ChannelExec;
import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.stream.Collectors;

class ChannelExecTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;
    private Session session;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
    }

    @Test
    void exec()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.connect();

        final ChannelExec channel = session.openChannel(ChannelExec.NAME);
        channel.setCommand("ls -la");
        channel.connect();

        final String out;

        try (InputStream is = channel.getInputStream();
             InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
             BufferedReader reader = new BufferedReader(isr)) {

            out = reader.lines().collect(Collectors.joining("\n"));
        }
        System.out.println(out);

        session.disconnect();
    }
}
