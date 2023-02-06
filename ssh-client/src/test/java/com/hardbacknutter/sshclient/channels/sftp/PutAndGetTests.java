package com.hardbacknutter.sshclient.channels.sftp;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ChannelSftp;
import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.DbgProgressListener;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.stream.Stream;

class PutAndGetTests
        extends BaseConnectionTest {

    private static final int ZIP = 1;
    private Session session;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
    }

    @NonNull
    private static Stream<Arguments> getArgs() {
        return Stream.of(
                Arguments.of("long.txt", 0),
                Arguments.of(".bashrc", 10)
        );
    }

    @ParameterizedTest
    @MethodSource("getArgs")
    void sftp_get_is_offset(@NonNull final String filename,
                            final long offset)
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        try (InputStream is = channel.get(filename, new DbgProgressListener(session), offset);
             Reader reader = new InputStreamReader(is, StandardCharsets.UTF_8);
             BufferedReader br = new BufferedReader(reader, 50000)) {
            String line;
            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }
        }
        session.disconnect();
    }


    @Test
    void sftp_get_f_d()
            throws SshException, GeneralSecurityException, IOException {
        ChannelSftp channel;

//        session = sshClient.getSession(USERNAME, HOST, PORT);
//        session.setPassword(PASSWORD);
//        session.connect();
//        channel = session.openChannel(ChannelSftp.NAME);
//        channel.connect();
//        channel.get("test5m", "C:\\tmp\\ssh", new DbgProgressListener(session));
//        session.disconnect();


        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.connect();

        channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        channel.put("C:/tmp/ssh/test5m", "k1", new DbgProgressListener(session));

        session.disconnect();
    }

    @Test
    void sftp_get_f_f()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        channel.get(".bashrc", "C:\\tmp\\ssh\\" + "f" + RANDOM.nextInt(),
                    new DbgProgressListener(session));

        session.disconnect();
    }

    @Test
    void sftp_get_os()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        try (FileOutputStream fw = new FileOutputStream("C:\\tmp\\ssh\\"
                                                                + "f" + RANDOM.nextInt())) {
            channel.get(".bashrc", fw, new DbgProgressListener(session));
        }

        session.disconnect();
    }


}
