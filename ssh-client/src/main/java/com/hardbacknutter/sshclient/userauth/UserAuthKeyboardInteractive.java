package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Locale;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4256">
 * RFC 4256 Generic Message Exchange Authentication for the SSH</a>
 */
public class UserAuthKeyboardInteractive
        implements UserAuth {

    public static final String METHOD = "keyboard-interactive";

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
                   SshTooManyAuthAttemptException, SshPartialAuthException,
                   SshAuthCancelException {

        if (userinfo != null && !(userinfo instanceof UIKeyboardInteractive)) {
            return false;
        }

        byte[] password = authPassword;

        String dest = username + "@" + session.getHost();
        if (session.getPort() != 22) {
            dest += (":" + session.getPort());
        }

        Packet packet = new Packet();

        boolean cancel = false;

        final int maxAuthAttempts = config.getIntValue(
                HostConfig.NUMBER_OF_PASSWORD_PROMPTS,
                HostConfig.DEFAULT_NUMBER_OF_PASSWORD_PROMPTS);
        int attemptsLeft = maxAuthAttempts;

        while (true) {
            if (attemptsLeft == 0) {
                throw new SshTooManyAuthAttemptException(METHOD, maxAuthAttempts);
            }

            // send
            // byte      SSH_MSG_USERAUTH_REQUEST(50)
            // string    user name (ISO-10646 UTF-8, as defined in [RFC-2279])
            // string    service name (US-ASCII) "ssh-userauth" ? "ssh-connection"
            // string    "keyboard-interactive" (US-ASCII)
            // string    language tag (as defined in [RFC-3066])
            // string    sub-methods (ISO-10646 UTF-8)
            packet.startCommand(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                  .putString(username)
                  .putString(UserAuth.SSH_CONNECTION)
                  .putString(METHOD)
                  .putString("")
                  .putString("");
            io.write(packet);

            boolean firstTime = true;
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

                    if (firstTime) {
                        return false;
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

                } else if (command == SshConstants.SSH_MSG_USERAUTH_INFO_REQUEST) {
                    firstTime = false;
                    packet.startReadingPayload();
                    packet.getByte(); // command
                    final String name = packet.getJString();
                    final String instruction = packet.getJString();
                    packet.skipString(/* language_tag */);
                    final int num_prompts = packet.getInt();
                    final String[] prompt = new String[num_prompts];
                    final boolean[] echo = new boolean[num_prompts];
                    for (int i = 0; i < num_prompts; i++) {
                        prompt[i] = packet.getJString();
                        echo[i] = packet.getBoolean();
                    }

                    byte[][] response = null;

                    if (password != null &&
                            prompt.length == 1 &&
                            !echo[0] &&
                            prompt[0].toLowerCase(Locale.ENGLISH).contains("password:")) {
                        response = new byte[1][];
                        response[0] = password;
                        password = null;
                    } else if (num_prompts > 0
                            || (!name.isEmpty() || !instruction.isEmpty())) {
                        if (userinfo != null) {
                            final UIKeyboardInteractive kbi = (UIKeyboardInteractive) userinfo;
                            final String[] _response = kbi.promptKeyboardInteractive(
                                    dest,
                                    name,
                                    instruction,
                                    prompt,
                                    echo);
                            if (_response != null) {
                                response = new byte[_response.length][];
                                for (int i = 0; i < _response.length; i++) {
                                    response[i] = _response[i].getBytes(StandardCharsets.UTF_8);
                                }
                            }
                        }
                    }

                    // byte      SSH_MSG_USERAUTH_INFO_RESPONSE(61)
                    // int       num-responses
                    // string    response[1] (ISO-10646 UTF-8)
                    // ...
                    // string    response[num-responses] (ISO-10646 UTF-8)
                    packet.startCommand(SshConstants.SSH_MSG_USERAUTH_INFO_RESPONSE);
                    if (num_prompts > 0 &&
                            (response == null ||  // cancel
                                    num_prompts != response.length)) {

                        if (response == null) {
                            // working around the bug in OpenSSH ;-<
                            packet.putInt(num_prompts);
                            for (int i = 0; i < num_prompts; i++) {
                                packet.putString("");
                            }
                        } else {
                            packet.putInt(0);
                        }

                        if (response == null) {
                            cancel = true;
                        }
                    } else {
                        packet.putInt(num_prompts);
                        for (int i = 0; i < num_prompts; i++) {
                            packet.putString(response[i]);
                        }
                    }
                    io.write(packet);

                } else {
                    return false;
                }
            }

            if (cancel) {
                throw new SshAuthCancelException(METHOD);
            }
        }
    }
}
