package com.hardbacknutter.sshclient.channels.forward;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.hostconfig.HostConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityImpl;
import com.hardbacknutter.sshclient.identity.IdentityRepository;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.userauth.SshAuthCancelException;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.SshConstants;
import com.hardbacknutter.sshclient.utils.SshException;

/**
 * Internal use-only channel.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04">
 *         SSH Agent Protocol draft-miller-ssh-agent-04</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1">
 *         SSH Agent Protocol draft-miller-ssh-agent-04, section 5.1 Message numbers</a>
 */
public class ChannelAgentForwarding
        extends ForwardingChannel {

    public static final String NAME = "auth-agent@openssh.com";

    /** The standard Java resource bundle with (translated) messages. */
    private static final String USER_MESSAGES = "msg.usermessages";
    // legacy SSH protocol version 1: 1-4, 7-9 and 24 (inclusive).
    private static final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
    private static final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;

    private static final byte SSH_AGENT_SUCCESS = 6;

    private static final byte SSH_AGENT_FAILURE = 5;
    /**
     * @see <a href="https://github.com/openssh/openssh-portable/blob/master/authfd.h">
     *         Extended failure messages</a>
     */
    private static final byte SSH2_AGENT_FAILURE = 30;

    private static final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
    private static final byte SSH_AGENT_IDENTITIES_ANSWER = 12;

    private static final byte SSH2_AGENTC_SIGN_REQUEST = 13;
    private static final byte SSH_AGENT_SIGN_RESPONSE = 14;

    /**
     * {@link #SSH2_AGENTC_SIGN_REQUEST flags}
     * Two flags are currently defined for signature request messages:
     * SSH_AGENT_RSA_SHA2_256 and SSH_AGENT_RSA_SHA2_512.  These two flags
     * are only valid for "ssh-rsa" keys and request that the agent return a
     * signature using the "rsa-sha2-256" or "rsa-sha2-512" signature
     * methods respectively.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.3>
     *         RFC draft 4, section 5.3</a>
     */
    private static final int SSH_AGENT_RSA_SHA2_256 = 2;
    private static final int SSH_AGENT_RSA_SHA2_512 = 4;

    private static final byte SSH2_AGENTC_ADD_IDENTITY = 17;
    private static final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
    private static final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
    //    private static final byte SSH2_AGENTC_ADD_ID_CONSTRAINED = 25;

    //    /* smart card */
    //    private static final byte SSH_AGENTC_ADD_SMARTCARD_KEY = 20;
    //    private static final byte SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21;
    //    private static final byte SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26;

    //    /* lock/unlock the agent */
    //    private static final byte SSH_AGENTC_LOCK = 22;
    //    private static final byte SSH_AGENTC_UNLOCK = 23;

    // Defined in RFC, but not in openssh sources
    //    private static final byte SSH_AGENTC_EXTENSION = 27;
    //    private static final byte SSH_AGENT_EXTENSION_FAILURE = 28;

    private final Buffer rbuf;

    /**
     * The buffer we write to, and embed as channel data in {@link #packet}.
     */
    private final Buffer responseBuffer;
    /**
     * The packet we send to the remote.
     * Only created once and reused.
     */
    private Packet packet;

    ChannelAgentForwarding(@NonNull final SessionImpl session) {
        super(NAME, session);

        rbuf = new Buffer();
        responseBuffer = new Buffer();

        connected = true;
    }

    /**
     * The channel transfer loop.
     */
    @Override
    protected void run() {
        // just confirm open or fail, and we're done here.
        // Actual forwarding is done on demand when the session receives
        // SSH_MSG_CHANNEL_DATA and sends it to #writeData
        try {
            sendChannelOpenConfirmation();

        } catch (final Exception e) {
            sendChannelOpenFailure(SshConstants.SSH_OPEN_CONNECT_FAILED);
            disconnect();
        }
    }

    @Override
    protected void writeData(@NonNull final byte[] bytes,
                             final int offset,
                             final int length)
            throws IOException, GeneralSecurityException {

        rbuf.shiftBuffer();
        if (rbuf.data.length < rbuf.writeOffset + length) {
            final byte[] tmpBuf = new byte[rbuf.getReadOffSet() + length];
            System.arraycopy(rbuf.data, 0, tmpBuf, 0, rbuf.data.length);
            rbuf.data = tmpBuf;
        }

        rbuf.putBytes(bytes, offset, length);

        // Messages consist of a length, type and contents.
        // uint32                    message length
        // byte                      message type
        // byte[message length - 1]  message contents
        final int messageLength = rbuf.getInt();
        if (messageLength > rbuf.availableToRead()) {
            rbuf.setReadOffSet(rbuf.getReadOffSet() - 4);
            return;
        }

        final byte messageType = rbuf.getByte();

        responseBuffer.reset();

        session.getLogger().log(Logger.DEBUG, () -> "Agent channel msg: " + messageType);

        switch (messageType) {
            case SSH2_AGENTC_SIGN_REQUEST: {
                // byte      SSH_AGENTC_SIGN_REQUEST
                // string    key blob
                // string    data
                // uint32    flags
                final byte[] keyBlob = rbuf.getString();
                final byte[] dataToSign = rbuf.getString();
                final int flags = rbuf.getInt();

                final UserInfo userinfo = session.getUserInfo();
                Identity identity = null;
                final IdentityRepository identityRepository = session.getIdentityRepository();
                synchronized (identityRepository) {
                    for (final Identity _identity : identityRepository.getIdentities()) {
                        if (Arrays.equals(keyBlob, _identity.getSshEncodedPublicKey())) {
                            boolean encrypted = _identity.isEncrypted();
                            if (encrypted && userinfo != null) {
                                try {
                                    attemptDecryption(identityRepository, _identity, userinfo);
                                } catch (final SshException ignore) {
                                }
                                encrypted = _identity.isEncrypted();
                            }

                            if (!encrypted) {
                                identity = _identity;
                                break;
                            }
                        }
                    }
                }

                byte[] signature = null;
                if (identity != null) {
                    String sigAlg = identity.getHostKeyAlgorithm();
                    if (HostKeyAlgorithm.isRSA(sigAlg)) {
                        if ((flags & SSH_AGENT_RSA_SHA2_512) != 0) {
                            sigAlg = HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_512;
                        } else if ((flags & SSH_AGENT_RSA_SHA2_256) != 0) {
                            sigAlg = HostKeyAlgorithm.SIG_ONLY_RSA_SHA2_256;
                        } else {
                            sigAlg = HostKeyAlgorithm.SSH_RSA;
                        }
                    }
                    signature = identity.getSignature(dataToSign, sigAlg);
                }

                if (signature == null) {
                    responseBuffer.putByte(SSH2_AGENT_FAILURE);
                } else {
                    responseBuffer.putByte(SSH_AGENT_SIGN_RESPONSE)
                                  .putString(signature);
                }
                break;
            }
            case SSH2_AGENTC_REQUEST_IDENTITIES: {
                responseBuffer.putByte(SSH_AGENT_IDENTITIES_ANSWER);
                final IdentityRepository identityRepository = session.getIdentityRepository();
                synchronized (identityRepository) {
                    // collect all the ones with a public key.
                    // (dev note: no stream() as getPublicKeyBlob() can throw)
                    final List<Identity> toSend = new ArrayList<>();
                    for (final Identity identity : identityRepository.getIdentities()) {
                        if (identity.getSshEncodedPublicKey() != null) {
                            toSend.add(identity);
                        }
                    }

                    responseBuffer.putInt(toSend.size());
                    for (final Identity identity : toSend) {
                        //noinspection DataFlowIssue
                        responseBuffer.putString(identity.getSshEncodedPublicKey())
                                      // comment
                                      .putString("");
                    }
                }
                break;
            }
            case SSH2_AGENTC_ADD_IDENTITY: {
                // byte      SSH_AGENTC_ADD_IDENTITY
                // string    key type
                // byte[]    key contents
                // string    key comment
                final byte[] keyBlob = new byte[rbuf.availableToRead()];
                rbuf.getBytes(keyBlob);
                boolean result = false;
                final IdentityRepository identityRepository = session.getIdentityRepository();
                try {
                    result = identityRepository.add(
                            IdentityImpl.fromKeyData(session.getConfig(),
                                                     "from SSHAgent:", keyBlob, null));
                } catch (final Exception ignore) {
                    // ignore ALL, just don't add the identity
                }
                responseBuffer.putByte(result ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE);
                break;
            }
            case SSH2_AGENTC_REMOVE_IDENTITY: {
                // byte     SSH_AGENTC_REMOVE_IDENTITY
                // string   key blob
                final byte[] keyBlob = rbuf.getString();
                try {
                    session.getIdentityRepository()
                           .remove(keyBlob);
                } catch (final SshException ignore) {
                }
                responseBuffer.putByte(SSH_AGENT_SUCCESS);
                break;
            }
            case SSH2_AGENTC_REMOVE_ALL_IDENTITIES: {
                try {
                    session.getIdentityRepository()
                           .removeAll();
                } catch (final SshException ignore) {
                }
                responseBuffer.putByte(SSH_AGENT_SUCCESS);
                break;
            }

            case SSH_AGENTC_REQUEST_RSA_IDENTITIES:
            case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
            default: {
                rbuf.moveWritePosition(rbuf.availableToRead() - 1);
                responseBuffer.putByte(SSH_AGENT_FAILURE);
                break;
            }
        }

        final byte[] response = responseBuffer.getPayload();

        if (packet == null) {
            packet = new Packet(remoteMaxPacketSize);
        }
        // the length of the response string (4 bytes for the len prefix)
        final int dataLength = 4 + response.length;
        //TODO: add optimization reusing the response buffer as the packet buffer ?
        packet.init(SshConstants.SSH_MSG_CHANNEL_DATA)
              .putInt(getRecipient())
              .putInt(dataLength)
              .putString(response);

        try {
            sendChannelDataPacket(packet, dataLength);
        } catch (final Exception ignore) {
        }
    }

    @Override
    public void eofFromRemote() {
        super.eofFromRemote();
        sendEOF();
    }

    /**
     * TODO: {@link com.hardbacknutter.sshclient.userauth.UserAuthPublicKey}
     * where duplicate code lives
     */
    private void attemptDecryption(@NonNull final IdentityRepository identityRepository,
                                   @NonNull final Identity identity,
                                   @NonNull final UserInfo userinfo)
            throws GeneralSecurityException, IOException, SshAuthCancelException {

        final ResourceBundle rb = ResourceBundle.getBundle(USER_MESSAGES);
        final String prompt = rb.getString("PROMPT_PASSPHRASE");

        // loop to allow the user multiple attempts at entering the passphrase
        int attemptsLeft = getSession().getConfig()
                                       .getIntValue(HostConfig.NUMBER_OF_PASSWORD_PROMPTS,
                                                    HostConfig.DEFAULT_NUMBER_OF_PASSWORD_PROMPTS);

        byte[] passphrase = null;
        try {
            do {
                if (userinfo.promptPassphrase(prompt, identity.getName())) {
                    passphrase = userinfo.getPassphrase();
                    if (passphrase == null) {
                        // We were promised a passphrase, but it was null
                        // -> the user wants to cancel
                        throw new SshAuthCancelException("");
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

}
