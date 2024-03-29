package com.hardbacknutter.sshclient.channels.sftp;

import com.hardbacknutter.sshclient.ChannelSftp;
import com.hardbacknutter.sshclient.Constants;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.connections.BaseConnectionTest;
import com.hardbacknutter.sshclient.utils.SshException;

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

        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
        session.connect();

        final ChannelSftp channel = session.openChannel(ChannelSftp.NAME);
        channel.connect();

        System.out.println("Server version=" + channel.getServerVersion());

        System.out.println("pwd=" + channel.pwd());

        channel.cd(".ssh");

        System.out.println("pwd=" + channel.pwd());

        channel.cd("..");

        session.disconnect();
    }

    @Test
    void sftp_ls()
            throws SshException, GeneralSecurityException, IOException {

        session = sshClient.getSession(Constants.USERNAME, Constants.HOST, Constants.PORT);
        session.setPassword(Constants.PASSWORD);
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
