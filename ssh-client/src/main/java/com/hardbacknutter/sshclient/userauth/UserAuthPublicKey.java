package com.hardbacknutter.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.net.ProtocolException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.PacketIO;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;
import com.hardbacknutter.sshclient.utils.SshConstants;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252#section-7">
 *         RFC 4252 SSH Authentication Protocol,
 *         section 7. Public Key Authentication Method: "publickey"</a>
 */
public class UserAuthPublicKey
        implements UserAuth {

    /** The standard Java resource bundle with (translated) messages. */
    private static final String USER_MESSAGES = "msg.usermessages";

    public static final String METHOD = "publickey";

    /**
     * byte      SSH_MSG_USERAUTH_PK_OK
     * string    public key algorithm name from the request
     * string    public key blob from the request
     */
    private static final byte SSH_MSG_USERAUTH_PK_OK = 60;

    private final List<String> rsaMethods = new ArrayList<>();
    private final List<String> nonRsaMethods = new ArrayList<>();
    private String username;
    @Nullable
    private UserInfo userinfo;
    private String prompt;

    private SshClientConfig config;

    @Override
    public void init(@NonNull final SshClientConfig config,
                     @NonNull final String username,
                     @Nullable final UserInfo userinfo)
            throws NoSuchAlgorithmException {

        this.config = config;
        this.username = username;
        this.userinfo = userinfo;

        for (final String name : ImplementationFactory.getPublicKeyAcceptedAlgorithms(config)) {
            if (HostKeyAlgorithm.isRSA(name)) {
                rsaMethods.add(name);
            } else {
                nonRsaMethods.add(name);
            }
        }

        final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
        prompt = rb.getString("PROMPT_PASSPHRASE");
    }

    @Override
    public boolean authenticate(@NonNull final Session session,
                                @NonNull final PacketIO io,
                                @Nullable final byte[] password)
            throws IOException, GeneralSecurityException, SshAuthCancelException,
                   SshPartialAuthException {

        final IdentityRepository identityRepository = session.getIdentityRepository();
        synchronized (identityRepository) {
            for (final Identity identity : identityRepository.getIdentities()) {

                boolean encrypted = identity.isEncrypted();
                if (encrypted && userinfo != null) {
                    attemptDecryption(identityRepository, identity);
                    encrypted = identity.isEncrypted();
                }

                if (!encrypted) {
                    List<String> allAlgorithms = filterAlgorithms(session, identity);
                    if (allAlgorithms != null) {
                        final byte[] publicKeyBlob = identity.getSshEncodedPublicKey();

                        String preAuthAlgorithm = null;
                        if (publicKeyBlob != null) {
                            preAuthAlgorithm = preAuth(session, io, allAlgorithms, publicKeyBlob);
                            if (preAuthAlgorithm == null) {
                                // try next identity
                                continue;
                            }
                        }

                        // Use the algorithm which did a successful pre-auth,
                        // otherwise we'll just have to try all algorithms
                        if (preAuthAlgorithm != null) {
                            allAlgorithms = new ArrayList<>();
                            allAlgorithms.add(preAuthAlgorithm);
                        }

                        if (authenticate(io, session, identity, allAlgorithms, publicKeyBlob)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    private void attemptDecryption(@NonNull final IdentityRepository identityRepository,
                                   @NonNull final Identity identity)
            throws GeneralSecurityException, IOException, SshAuthCancelException {

        // sanity check
        Objects.requireNonNull(userinfo);

        // loop to allow the user multiple attempts at entering the passphrase
        int attemptsLeft = config.getIntValue(HostConfig.NUMBER_OF_PASSWORD_PROMPTS,
                                              HostConfig.DEFAULT_NUMBER_OF_PASSWORD_PROMPTS);

        byte[] passphrase = null;
        try {
            do {
                if (userinfo.promptPassphrase(prompt, identity.getName())) {
                    passphrase = userinfo.getPassphrase();
                    if (passphrase == null) {
                        // We were promised a passphrase, but it was null
                        // -> the user wants to cancel
                        throw new SshAuthCancelException(METHOD);
                    }
                }

                if (identity.decrypt(passphrase)) {
                    identityRepository.update(identity);
                    return;
                }


                if (passphrase != null) {
                    Arrays.fill(passphrase, (byte) 0);
                    passphrase = null;
                }
                attemptsLeft--;
            } while (attemptsLeft > 0 && identity.isEncrypted());

        } finally {
            if (passphrase != null) {
                Arrays.fill(passphrase, (byte) 0);
            }
        }
    }

    @Nullable
    private List<String> filterAlgorithms(@NonNull final Session session,
                                          @NonNull final Identity identity)
            throws GeneralSecurityException {

        final String identityKeyAlgorithm = identity.getHostKeyAlgorithm();

        if (HostKeyAlgorithm.SSH_RSA.equals(identityKeyAlgorithm) && !rsaMethods.isEmpty()) {
            return rsaMethods;

        } else if (!nonRsaMethods.isEmpty()) {
            return nonRsaMethods.stream()
                                .filter(identityKeyAlgorithm::equals)
                                .collect(Collectors.toList());
        }

        if (session.getLogger().isEnabled(Logger.DEBUG)) {
            session.getLogger().log(Logger.DEBUG, () -> identityKeyAlgorithm
                    + " cannot be used as public key type for " + identity.getName());
        }

        return null;
    }

    /**
     * To avoid unnecessary processing and user interaction,
     * the following message is provided for querying whether
     * authentication using the "publickey" method would be acceptable.
     * <p>
     * byte      SSH_MSG_USERAUTH_REQUEST
     * ...
     *
     * @return the algorithm name for which we successfully pre-authenticated,
     * or {@code null} if pre-auth failed.
     */
    @Nullable
    private String preAuth(@NonNull final Session session,
                           @NonNull final PacketIO io,
                           @NonNull final List<String> algorithms,
                           @NonNull final byte[] publicKeyBlob)
            throws IOException, GeneralSecurityException {

        for (final String algorithm : algorithms) {
            // query whether authentication using the "publickey" method would be acceptable.
            //
            // byte      SSH_MSG_USERAUTH_REQUEST(50)
            // string    user name
            // string    service name ("ssh-connection")
            // string    "publickey"
            // boolean   FALSE
            // string    public key algorithm name
            // string    public key blob
            Packet packet = new Packet(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                    .putString(username)
                    .putString(UserAuth.SSH_CONNECTION)
                    .putString(METHOD)
                    .putBoolean(false)
                    .putString(algorithm)
                    .putString(publicKeyBlob);
            io.write(packet);

            // The server MUST respond to this message with either
            //    SSH_MSG_USERAUTH_FAILURE or with SSH_MSG_USERAUTH_PK_OK

            packet = io.read();
            final byte command = packet.getCommand();
            packet.startReadingPayload();

            if (command == SSH_MSG_USERAUTH_PK_OK) {
                //       byte      SSH_MSG_USERAUTH_PK_OK
                //       string    public key algorithm name from the request
                //       string    public key blob from the request
                if (session.getLogger().isEnabled(Logger.DEBUG)) {
                    session.getLogger().log(Logger.DEBUG, () -> algorithm + " preAuth success");
                }
                return algorithm;

            } else if (command != SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                // This should never happen
                throw new ProtocolException("preAuth failure; received command=" + command);
            }
            if (session.getLogger().isEnabled(Logger.DEBUG)) {
                session.getLogger().log(Logger.DEBUG, () -> algorithm + " preAuth failure");
            }
            // try next algorithm
        }
        // Pre-auth failed
        return null;
    }

    /**
     * @return {@code true} if successfully authenticated
     */
    private boolean authenticate(@NonNull final PacketIO io,
                                 @NonNull final Session session,
                                 @NonNull final Identity identity,
                                 @NonNull final List<String> preAuthSuccessful,
                                 @Nullable byte[] publicKeyBlob)
            throws GeneralSecurityException, IOException, SshPartialAuthException {

        if (publicKeyBlob == null) {
            publicKeyBlob = identity.getSshEncodedPublicKey();
            if (publicKeyBlob == null) {
                return false;
            }
        }

        for (final String algorithm : preAuthSuccessful) {
            if (!sendAuthPacket(io, session, identity, publicKeyBlob, algorithm)) {
                return false;
            }

            Packet packet;
            while (true) {
                packet = io.read();
                final byte command = packet.getCommand();

                switch (command) {
                    case SshConstants.SSH_MSG_USERAUTH_SUCCESS: {
                        if (session.getLogger().isEnabled(Logger.DEBUG)) {
                            session.getLogger().log(Logger.DEBUG, () ->
                                    algorithm + " auth success");
                        }
                        return true;
                    }
                    case SshConstants.SSH_MSG_USERAUTH_BANNER: {
                        if (userinfo != null) {
                            packet.startReadingPayload();
                            packet.getByte(); // command
                            final String message = packet.getJString();
                            packet.skipString(/* language_tag */);

                            userinfo.showMessage(message);
                        }
                        // keep looping
                        break;
                    }
                    case SshConstants.SSH_MSG_USERAUTH_FAILURE: {
                        packet.startReadingPayload();
                        packet.getByte(); // command

                        final byte[] authMethodsToTryNext = packet.getString();
                        final boolean partial_success = packet.getBoolean();
                        if (partial_success) {
                            throw new SshPartialAuthException(METHOD, authMethodsToTryNext);
                        }
                        return false;
                    }
                    default: {
                        if (session.getLogger().isEnabled(Logger.DEBUG)) {
                            session.getLogger().log(Logger.DEBUG, () -> algorithm
                                    + " auth failure; received command=" + command);
                        }
                        return false;
                    }
                }
            }
        }
        return false;
    }

    /**
     * @return {@code true} if successfully send
     */
    private boolean sendAuthPacket(@NonNull final PacketIO io,
                                   @NonNull final Session session,
                                   @NonNull final Identity identity,
                                   @NonNull final byte[] publicKeyBlob,
                                   @NonNull final String publicKeyAlgorithm)
            throws IOException {

        // perform actual authentication
        // byte      SSH_MSG_USERAUTH_REQUEST(50)
        // string    user name
        // string    service name ("ssh-connection")
        // string    "publickey"
        // boolean   TRUE
        // string    public key algorithm name
        // string    public key blob
        // string    signature
        final Packet packet = new Packet(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                .putString(username)
                .putString(UserAuth.SSH_CONNECTION)
                .putString(METHOD)
                .putBoolean(true)
                .putString(publicKeyAlgorithm)
                .putString(publicKeyBlob);

        // The value of 'signature' is a signature by the corresponding private
        // key over the following data, in the following order:
        //
        //      string    session identifier
        // +
        //      byte      SSH_MSG_USERAUTH_REQUEST
        //      string    user name
        //      string    service name ("ssh-connection")
        //      string    "publickey"
        //      boolean   TRUE
        //      string    public key algorithm name
        //      string    public key blob

        final byte[] dataToSign = new Buffer()
                .putString(Objects.requireNonNull(session.getSessionId()))
                .putBytes(packet.data, Packet.HEADER_LEN,
                          packet.writeOffset - Packet.HEADER_LEN)
                .getPayload();

        final byte[] signature_blob;
        try {
            signature_blob = identity.getSignature(dataToSign, publicKeyAlgorithm);
            // string    signature
            packet.putString(signature_blob);
            io.write(packet);
            return true;

        } catch (final GeneralSecurityException e) {
            // signing failed; e.g. key length too long,...
            if (session.getLogger().isEnabled(Logger.DEBUG)) {
                session.getLogger().log(Logger.DEBUG, () ->
                        publicKeyAlgorithm + " signature failure");
            }
            return false;
        }
    }
}
