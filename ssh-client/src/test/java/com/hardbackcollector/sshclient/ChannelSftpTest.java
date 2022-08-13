package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.connections.BaseConnectionTest;
import com.hardbackcollector.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class ChannelSftpTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;
    private Session session;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
    }

    // This test will fail.
    // The sun.nio.cs.StreamDecoder seems to be created with the default 8192.
    // Setting our own buffered reader to less than 8192 (instead of the 50_000)
    // does not solve the issue, as Java seems to use the default StreamDecoder
    // constructor. i.e. one of the StreamDecoder forInputStreamReader
    // which always use the default 8192 buffer.
    // Is this a Java bug ??
    //
    //
    // newPosition > limit: (12711 > 8192)
    //java.lang.IllegalArgumentException: newPosition > limit: (12711 > 8192)
    //	at java.base/java.nio.Buffer.createPositionException(Buffer.java:341)
    //	at java.base/java.nio.Buffer.position(Buffer.java:316)
    //	at java.base/java.nio.ByteBuffer.position(ByteBuffer.java:1516)
    //	at java.base/sun.nio.cs.StreamDecoder.readBytes(StreamDecoder.java:276)
    //	at java.base/sun.nio.cs.StreamDecoder.implRead(StreamDecoder.java:313)
    //	at java.base/sun.nio.cs.StreamDecoder.read(StreamDecoder.java:188)
    //	at java.base/java.io.InputStreamReader.read(InputStreamReader.java:177)
    //	at java.base/java.io.BufferedReader.fill(BufferedReader.java:162)
    //	at java.base/java.io.BufferedReader.readLine(BufferedReader.java:329)
    //	at java.base/java.io.BufferedReader.readLine(BufferedReader.java:396)
    //	at com.hardbackcollector.sshclient.ChannelSftpTest.sftp_get_is_offset(ChannelSftpTest.java:59)
    //	at com.hardbackcollector.sshclient.ChannelSftpTest.sftp_get_is(ChannelSftpTest.java:35)
    @Test
    void sftp_get_is()
            throws SshException, GeneralSecurityException, IOException {
        sftp_get_is_offset("long.txt", 0);
    }

    @Test
    void sftp_get_is_offset()
            throws SshException, GeneralSecurityException, IOException {
        sftp_get_is_offset(".bashrc", 10);
    }

    private void sftp_get_is_offset(@NonNull final String filename,
                                    final long offset)
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        try (InputStream is = channel.get(filename, new DbgSftpProgressMonitor(session), offset);
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

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        channel.get("/boot/kernel.img", "C:\\tmp\\ssh");

        session.disconnect();


        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        channel.put("C:/tmp/ssh/kernel.img", "k1");

        session.disconnect();
    }

    @Test
    void sftp_get_f_f()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        channel.get(".bashrc", "C:\\tmp\\ssh\\" + "f" + RANDOM.nextInt());

        session.disconnect();
    }

    @Test
    void sftp_get_os()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        try (FileOutputStream fw = new FileOutputStream("C:\\tmp\\ssh\\"
                + "f" + RANDOM.nextInt())) {
            channel.get(".bashrc", fw);
        }

        session.disconnect();
    }


    @Test
    void sftp_cd()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        System.out.println("Server version=" + channel.getServerVersion());

        System.out.println("pwd=" + channel.pwd());

        channel.cd("log");

        System.out.println("pwd=" + channel.pwd());

        channel.cd("..");

        session.disconnect();
    }

    @Test
    void sftp_ls()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(USERNAME, HOST, PORT);
        session.setPassword(PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        channel.ls("").forEach(lsEntry -> System.out.println(
                ": {name='" + lsEntry.getFilename() + "',long='" + lsEntry.getLongname()
                        + "'}"));

        channel.ls("/").forEach(lsEntry -> System.out.println(
                "root: {name='" + lsEntry.getFilename() + "',long='" + lsEntry.getLongname()
                        + "'}"));

        session.disconnect();
    }
}
