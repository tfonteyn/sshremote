package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.ResourceBundle;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.SshConstants;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252#section-8">
 *         RFC 4252 SSH Authentication Protocol,
 *         section 8. Password Authentication Method: "password"</a>
 */
public class UserAuthPassword
        implements UserAuth {

    /** The standard Java resource bundle with (translated) messages. */
    private static final String USER_MESSAGES = "msg.usermessages";

    public static final String METHOD = "password";

    /**
     * byte      SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
     * string    prompt in ISO-10646 UTF-8 encoding [RFC3629]
     * string    language tag [RFC3066]
     */
    private static final byte SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

    private String username;
    @Nullable
    private UserInfo userinfo;

    private SshClientConfig config;

    @Override
    public void init(@NonNull final SshClientConfig config,
                     @NonNull final String username,
                     @Nullable final UserInfo userinfo) {
        this.config = config;
        this.username = username;
        this.userinfo = userinfo;
    }

    @Override
    public boolean authenticate(@NonNull final Session session,
                                @NonNull final PacketIO io,
                                @Nullable final byte[] authPassword)
            throws IOException, GeneralSecurityException,
                   SshAuthCancelException, SshPartialAuthException,
                   SshTooManyAuthAttemptException {

        byte[] password = authPassword;

        String dest = username + "@" + session.getHost();
        if (session.getPort() != 22) {
            dest += (":" + session.getPort());
        }

        Packet packet = new Packet();

        final int maxAuthAttempts = config.getIntValue(
                HostConfig.NUMBER_OF_PASSWORD_PROMPTS,
                HostConfig.DEFAULT_NUMBER_OF_PASSWORD_PROMPTS);
        int attemptsLeft = maxAuthAttempts;

        try {
            while (true) {
                if (attemptsLeft == 0) {
                    throw new SshTooManyAuthAttemptException(METHOD, maxAuthAttempts);
                }

                if (password == null) {
                    if (userinfo == null) {
                        return false;
                    } else {
                        final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
                        if (!userinfo.promptPassword(rb.getString("PROMPT_PASSWORD"), dest)) {
                            throw new SshAuthCancelException(METHOD);
                        }

                        password = userinfo.getPassword();
                        if (password == null) {
                            throw new SshAuthCancelException(METHOD);
                        }
                    }
                }

                // send
                // byte      SSH_MSG_USERAUTH_REQUEST(50)
                // string    user name
                // string    service name ("ssh-connection")
                // string    method ("password")
                // boolean   FALSE
                // string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
                packet.init(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                      .putString(username)
                      .putString(UserAuth.SSH_CONNECTION)
                      .putString(METHOD)
                      .putBoolean(false)
                      .putString(password);
                io.write(packet);

                while (true) {
                    packet = io.read();
                    final byte command = packet.getCommand();

                    if (command == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                        return true;

                    } else if (command == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                        packet.startReadingPayload();
                        packet.getByte(); // command
                        final byte[] authMethodsToTryNext = packet.getString();
                        final boolean partial_success = packet.getBoolean();
                        if (partial_success) {
                            throw new SshPartialAuthException(METHOD, authMethodsToTryNext);

                        }
                        attemptsLeft--;
                        break; // inner loop

                    } else if (command == SshConstants.SSH_MSG_USERAUTH_BANNER) {
                        if (userinfo != null) {
                            packet.startReadingPayload();
                            packet.getByte(); // command
                            final String message = packet.getJString();
                            packet.skipString(/* language_tag */);

                            userinfo.showMessage(message);
                        }

                    } else if (command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
                        packet.startReadingPayload();
                        packet.getByte(); // command
                        final byte[] prompt = packet.getString();
                        packet.skipString(/* language_tag */);
                        if (userinfo instanceof UIKeyboardInteractive) {
                            final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);

                            final UIKeyboardInteractive kbi = (UIKeyboardInteractive) userinfo;
                            final String[] response = kbi.promptKeyboardInteractive(
                                    dest,
                                    rb.getString("PASSWORD_CHANGE_REQUIRED"),
                                    new String(prompt, 0, prompt.length,
                                               StandardCharsets.UTF_8),
                                    new String[]{rb.getString("PROMPT_NEW_PASSWORD")},
                                    new boolean[]{false});
                            if (response == null) {
                                throw new SshAuthCancelException(METHOD);
                            }

                            final byte[] newPassword = response[0].getBytes(StandardCharsets.UTF_8);

                            // send
                            // byte      SSH_MSG_USERAUTH_REQUEST(50)
                            // string    user name
                            // string    service name ("ssh-connection")
                            // string    method ("password")
                            // boolean   TRUE
                            // string    plaintext old password (ISO-10646 UTF-8)
                            // string    plaintext new password (ISO-10646 UTF-8)
                            packet.init(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                                  .putString(username)
                                  .putString(UserAuth.SSH_CONNECTION)
                                  .putString(METHOD)
                                  .putBoolean(true)
                                  .putString(password)
                                  .putString(newPassword);
                            Arrays.fill(newPassword, (byte) 0);
                            io.write(packet);
                        } else {
                            if (userinfo != null) {
                                final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
                                userinfo.showMessage(rb.getString("PASSWORD_MUST_BE_CHANGED"));
                            }
                            return false;
                        }
                    } else {
                        // can't interact with the user, just fail
                        return false;
                    }
                }
            }
        } finally {
            if (password != null) {
                Arrays.fill(password, (byte) 0);
            }
        }
    }
}
