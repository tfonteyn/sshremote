package com.hardbackcollector.sshclient.channels.sftp;

import com.hardbackcollector.sshclient.ChannelSftp;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.connections.BaseConnectionTest;
import com.hardbackcollector.sshclient.utils.SshException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

class OtherTest
        extends BaseConnectionTest {

    private static final int ZIP = 1;
    private Session session;

    @BeforeEach
    void setup()
            throws IOException, GeneralSecurityException {
        super.setup(ZIPPER[ZIP]);
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

        System.out.println("home\n");
        channel.ls("").forEach(lsEntry -> System.out.println(
                ": {name='" + lsEntry.getFilename() + "',long='" + lsEntry.getLongname()
                        + "'}"));

//        channel.ls("/").forEach(lsEntry -> System.out.println(
//                "root: {name='" + lsEntry.getFilename() + "',long='" + lsEntry.getLongname()
//                        + "'}"));

        System.out.println("\ntxt only\n");
        channel.ls("*.txt").forEach(lsEntry -> System.out.println(
                ": {name='" + lsEntry.getFilename() + "',long='" + lsEntry.getLongname()
                        + "'}"));

        session.disconnect();
    }
}
