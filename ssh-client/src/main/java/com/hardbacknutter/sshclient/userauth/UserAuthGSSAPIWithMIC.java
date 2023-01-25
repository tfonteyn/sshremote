package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Implements the User Authentication method {@code gssapi-with-mic}
 * as described in RFC 4462, section 3, which works by using the
 * GSS-API on both client and server.
 * <p>
 * For now, we only support the mechanism {@code 1.2.840.113554.1.2.2},
 * i.e. Kerberos 5 authentication (but more could be added by simply
 * changing some private constants in the class, and adding the
 * corresponding GSSContext implementation).
 * </p>
 * <p>
 * For the actual method-specific calculations we use an implementation
 * of {@link UserAuthGSSContext} which wraps a GSS-API implementation.
 * We will get an implementation class name from the configuration,
 * then instantiate it with the no-argument constructor. To create a context,
 * the {@link UserAuthGSSContext#create create} method will be called. After this,
 * we initialize the context with {@link UserAuthGSSContext#init init} (using
 * maybe more than one such call) to authenticate the user. Then we use
 * once {@link UserAuthGSSContext#getMIC getMIC} to sign some data (containing the
 * SSH session identifier), increasing resistance against man-in-the-middle
 * attacks (where the session identifier will be different on both sides).
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4462">
 * RFC 4462 Generic Security Service Application Program Interface (GSS-API)
 * Authentication and Key Exchange for the SSH Protocol</a>
 */
public class UserAuthGSSAPIWithMIC
        implements UserAuth {

    public static final String METHOD = "gssapi-with-mic";

    private static final byte SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
    private static final byte SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
    // private static final byte SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
    private static final byte SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
    private static final byte SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
    private static final byte SSH_MSG_USERAUTH_GSSAPI_MIC = 66;


    private static final byte[][] supported_oid = {
            // OID 1.2.840.113554.1.2.2 in DER
            {(byte) 0x6, (byte) 0x9, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
                    (byte) 0x86, (byte) 0xf7, (byte) 0x12, (byte) 0x1, (byte) 0x2,
                    (byte) 0x2}
    };
    private static final String[] supported_method = {
            "gssapi-with-mic.krb5"
    };

    private static final byte[] INITIAL_TOKEN = new byte[0];

    private String username;
    @Nullable
    private UserInfo userinfo;

    private SshClientConfig config;

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
                                @Nullable final byte[] password)
            throws IOException, GeneralSecurityException, SshPartialAuthException {

        final byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);

        // https://datatracker.ietf.org/doc/html/rfc4462#section-3.2
        // send
        // byte      SSH_MSG_USERAUTH_REQUEST
        // string    user name (in ISO-10646 UTF-8 encoding)
        // string    service name (in US-ASCII)
        // string    "gssapi-with-mic" (US-ASCII method name)
        // uint32    n, the number of mechanism OIDs client supports
        // string[n] mechanism OIDs
        Packet packet = new Packet(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                .putString(usernameBytes)
                .putString(UserAuth.SSH_CONNECTION)
                .putString(METHOD)
                .putInt(supported_oid.length);
        for (final byte[] bytes : supported_oid) {
            packet.putString(bytes);
        }
        io.write(packet);

        String method = null;
        byte command;
        while (true) {
            packet = io.read();
            command = packet.getCommand();

            if (command == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                return false;

            } else if (command == SSH_MSG_USERAUTH_GSSAPI_RESPONSE) {
                packet.startReadingPayload();
                packet.getByte(); // command
                final byte[] message = packet.getString();

                for (int i = 0; i < supported_oid.length; i++) {
                    if (Arrays.equals(message, supported_oid[i])) {
                        method = supported_method[i];
                        break;
                    }
                }

                if (method == null) {
                    return false;
                }

                // success: we got a GSS response; more code below the loop
                break;

            } else if (command == SshConstants.SSH_MSG_USERAUTH_BANNER) {
                if (userinfo != null) {
                    packet.startReadingPayload();
                    packet.getByte(); // command
                    final String message = packet.getJString();
                    packet.skipString(/* language_tag */);

                    userinfo.showMessage(message);
                }
            } else {
                return false;
            }
        }

        final UserAuthGSSContext context;
        try {
            context = ImplementationFactory.loadClassOrThrow(
                    config, ImplementationFactory.USERAUTH_CONFIG_PREFIX + method,
                    UserAuthGSSContext.class);
        } catch (final Exception e) {
            return false;
        }

        try {
            context.create(username, session.getHost());
        } catch (final SshAuthException e) {
            return false;
        }

        byte[] token = INITIAL_TOKEN;

        while (!context.isEstablished()) {
            try {
                token = context.init(token, 0, token.length);
            } catch (final SshAuthException e) {
                // https://datatracker.ietf.org/doc/html/rfc4462#section-3.9
                // In the event that, during context establishment, a client's call to
                //   GSS_Init_sec_context()....
                // TODO: we SHOULD (but are not obliged) send ERRTOK.
                // byte        SSH_MSG_USERAUTH_GSSAPI_ERRTOK
                // string      error token
                return false;
            }

            // byte        SSH_MSG_USERAUTH_GSSAPI_TOKEN
            // string      data returned from either GSS_Init_sec_context()
            //             or GSS_Accept_sec_context()
            packet.startCommand(SSH_MSG_USERAUTH_GSSAPI_TOKEN)
                  .putString(token);
            io.write(packet);

            if (!context.isEstablished()) {
                packet = io.read();
                command = packet.getCommand();
                if (command == SSH_MSG_USERAUTH_GSSAPI_ERROR) {
                    // the server MAY send the following message to inform
                    //   the client of the details of the error before sending an
                    //   SSH_MSG_USERAUTH_FAILURE message.
                    // byte      SSH_MSG_USERAUTH_GSSAPI_ERROR
                    // uint32    major_status
                    // uint32    minor_status
                    // string    message
                    // string    language tag

                    // just skip the data...

                } else if (command == SSH_MSG_USERAUTH_GSSAPI_ERRTOK) {
                    // When a server sends this message, it MUST be followed by an
                    //   SSH_MSG_USERAUTH_FAILURE message, which is to be interpreted as
                    //   applying to the same authentication request.
                    // byte        SSH_MSG_USERAUTH_GSSAPI_ERRTOK
                    // string      error token

                    // just skip the data...
                }

                // as per above, look for the next message and unless
                // it's SSH_MSG_USERAUTH_FAILURE, loop
                packet = io.read();
                command = packet.getCommand();
                if (command == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                    return false;
                }

                packet.startReadingPayload();
                packet.getByte(); // command
                token = packet.getString();
            }
        }

        // https://datatracker.ietf.org/doc/html/rfc4462#section-3.5

        // string    session identifier
        // byte      SSH_MSG_USERAUTH_REQUEST
        // string    user name
        // string    service
        // string    "gssapi-with-mic"
        final Buffer micBuffer = new Buffer()
                .putString(Objects.requireNonNull(session.getSessionId()))
                .putByte(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                .putString(usernameBytes)
                .putString(UserAuth.SSH_CONNECTION)
                .putString(METHOD);

        final byte[] mic;
        try {
            mic = context.getMIC(micBuffer.data, 0, micBuffer.writeOffset);
        } catch (final SshAuthException e) {
            return false;
        }

        // send
        // byte      SSH_MSG_USERAUTH_GSSAPI_MIC
        // string    MIC
        packet.startCommand(SSH_MSG_USERAUTH_GSSAPI_MIC)
              .putString(mic);
        io.write(packet);

        context.dispose();

        packet = io.read();
        command = packet.getCommand();

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
        }
        return false;
    }
}
