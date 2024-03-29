package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.SshConstants;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252#section-5.2">
 *         RFC 4252 SSH Authentication Protocol,
 *         section 5.2. The "none" Authentication Request</a>
 */
public class UserAuthNone
        implements UserAuth {

    public static final String METHOD = "none";

    private String methods;

    private String username;
    @Nullable
    private UserInfo userinfo;

    @Override
    public void init(@NonNull final SshClientConfig config,
                     @NonNull final String username,
                     @Nullable final UserInfo userinfo) {
        this.username = username;
        this.userinfo = userinfo;
    }

    @Override
    public boolean authenticate(@NonNull final Session session,
                                @NonNull final PacketIO io,
                                @Nullable final byte[] password)
            throws IOException, GeneralSecurityException, SshAuthException {

        // send
        // byte      SSH_MSG_SERVICE_REQUEST(5)
        // string    service name "ssh-userauth"
        Packet packet = new Packet(SshConstants.SSH_MSG_SERVICE_REQUEST)
                .putString(UserAuth.SSH_USERAUTH);
        io.write(packet);

        session.getLogger().log(Logger.DEBUG, () -> "SSH_MSG_SERVICE_REQUEST sent");

        // If the server supports the service (and permits the client to use it),
        // it MUST respond with the following:
        //
        // byte      SSH_MSG_SERVICE_ACCEPT(6)
        // string    service name
        packet = io.read();

        if (packet.getCommand() != SshConstants.SSH_MSG_SERVICE_ACCEPT) {
            throw new SshAuthException("UserAuthNone received unexpected command="
                                       + packet.getCommand());
        }

        // byte      SSH_MSG_USERAUTH_REQUEST(50)
        // string    user name
        // string    service name ("ssh-connection")
        // string    method ("none")
        packet.init(SshConstants.SSH_MSG_USERAUTH_REQUEST)
              .putString(username)
              .putString(UserAuth.SSH_CONNECTION)
              .putString(METHOD);
        io.write(packet);

        while (true) {
            packet = io.read();
            final byte command = packet.getCommand();

            if (command == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                return true;

            } else if (command == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                packet.startReadingPayload();
                packet.getByte(); // command
                methods = packet.getJString();
                packet.getBoolean(); // partial_success
                return false;

            } else if (command == SshConstants.SSH_MSG_USERAUTH_BANNER) {
                if (userinfo != null) {
                    packet.startReadingPayload();
                    packet.getByte(); // command
                    final String message = packet.getJString();
                    packet.skipString(/* language_tag */);

                    userinfo.showMessage(message);
                }
            } else {
                throw new SshAuthException("UserAuthNone fail (" + command + ")");
            }
        }
    }

    /**
     * @return list of auth methods supported by the server
     */
    @NonNull
    public List<String> getMethods() {
        if (methods == null) {
            return new ArrayList<>();
        }

        return Arrays.asList(methods.split(","));
    }
}
