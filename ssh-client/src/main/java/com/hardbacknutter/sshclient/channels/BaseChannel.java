package com.hardbacknutter.sshclient.channels;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Channel;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.channels.io.IOStreams;
import com.hardbacknutter.sshclient.channels.io.MyPipedInputStream;
import com.hardbacknutter.sshclient.channels.io.PassiveOutputStream;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.transport.Transport;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The abstract base class for the different
 * types of channel which may be associated with a {@link Session}.
 *
 * @see Session#openChannel
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-5">
 * RFC 4254 SSH Connection Protocol, section 5. Channel Mechanism</a>
 */
public abstract class BaseChannel
        implements Channel {

    @SuppressWarnings("WeakerAccess")
    public static final int LOCAL_MAXIMUM_PACKET_SIZE = Packet.MAX_SIZE;
    /** Default: 1mb */
    @SuppressWarnings("WeakerAccess")
    public static final int LOCAL_DEFAULT_WINDOW_SIZE = 0x10_0000;


    /** Config option: Maximum Channel input buffer size. */
    @SuppressWarnings("WeakerAccess")
    public static final String MAX_INPUT_BUFFER_SIZE = "max_input_buffer_size";

    /**
     * Standard Channel packet header.
     * 1: SSH command byte
     * 4: recipient
     * 4: length of the "data" string
     * 4: length of the payload
     * == 13
     */
    protected static final int CHANNEL_PACKET_HEADER_LEN = 13;

    protected static final String ERROR_STREAM_CLOSED = "Stream is closed";
    protected static final String ERROR_SEQUENCE_MISMATCH = "Sequence mismatch";
    protected static final String ERROR_INVALID_TYPE_s = "Invalid type: ";

    protected static final String ERROR_SESSION_NOT_CONNECTED = "Session is closed";

    /** Local channel id generator. */
    private static final AtomicInteger channelIdGenerator = new AtomicInteger();

    @NonNull
    protected final IOStreams ioStreams;
    private static final int NO_RECIPIENT = -1;
    /** Channel type name. */
    @NonNull
    private final String type;
    /** LOCAL Unique ID for this channel instance. (incremental/generated). */
    private final int id;

    /**
     * {@code true} if the OPEN Packet was send to the remote, or in the case of a local
     * channel, the channel is ready for action.
     */
    protected boolean connected;
    /** Session instance this channel belongs to. */
    @NonNull
    protected final SessionImpl session;

    /**
     * Default local maximum packet size.
     *
     * @see #remoteMaxPacketSize
     */
    protected int localMaxPacketSize = LOCAL_MAXIMUM_PACKET_SIZE;
    /**
     * Remote maximum packet size: set by the server during initial channel communications.
     *
     * @see #localMaxPacketSize
     */
    protected int remoteMaxPacketSize;
    /**
     * local window size; default; we could have the initial size smaller, but we might just
     * as well use the maximum.
     */
    protected int localWindowSize = LOCAL_DEFAULT_WINDOW_SIZE;
    /**
     * remote window size
     * <p>
     * Note: a Raspberry Pi B+ with 512mb raspbian(from early 2021) reports:
     * - remoteWindowSize:     2mb.
     * - remoteMaxPacketSize: 32kb
     *
     * @see #localMaxPacketSize
     */
    protected long remoteWindowSize;
    /** Self reference. When set, we're running as a thread ready to accept incoming traffic. */
    @Nullable
    protected Thread channelThread;
    /** Local maximum window size. Maybe make this configurable ? */
    @SuppressWarnings({"FieldCanBeLocal", "FieldMayBeFinal"})
    private int maxLocalWindowSize = LOCAL_DEFAULT_WINDOW_SIZE;
    /** REMOTE Channel ID assigned by the SSH server to delegate packets. */
    private int recipient = NO_RECIPIENT;

    /** {@code true} if the remote confirmed the connection. */
    private boolean openConfirmationReceived;

    /**
     * {@code true} if we already send a CLOSE Packet to the remote;
     * or if we do not need to send one at disconnect time.
     * <p>
     * There are 3 possible states:
     * <ol>
     *     <li>connected==true && closePacketSend==false : fully connected/valid</li>
     *     <li>connected==true && closePacketSend==true : we're in the process of disconnecting</li>
     *     <li>connected==false: fully disconnected. (value of closePacketSend is irrelevant)</li>
     * </ol>
     */
    private boolean closePacketSend;

    /** Reply status from a channel request. */
    @NonNull
    private ReplyStatus reply = ReplyStatus.None;
    /** Connection timeout in milliseconds (zero indicates no timeout). */
    private int connectTimeout;
    /** The number of outstanding global requests waiting to be notified for this channel. */
    private int notifyMe;
    /** {@code true} if the local output has reached EOF. */
    private boolean eofLocal;
    /** {@code true} if the remote output has reached EOF. */
    private boolean eofRemote;

    private int openFailureCode;
    private String openFailureMessage;

    protected BaseChannel(@NonNull final String type,
                          @NonNull final SessionImpl session) {
        this.type = type;
        this.session = session;
        this.id = channelIdGenerator.getAndIncrement();

        ioStreams = new IOStreams();

        //TODO: We really shouldn't let 'this' escape before the sub-class constructor is done...
        session.registerChannel(this);
    }

    /**
     * Opens the channel. This sends a {@code SSH_MSH_CHANNEL_OPEN} message
     * and waits until the response is received.
     * <p>
     * This can (and is) overridden by some subclasses.
     *
     * @param connectTimeout the maximum time to wait for the channel to be
     *                       established, in milliseconds. If 0, we wait as long
     *                       as needed (but at most 1000 times 50 milliseconds each).
     */
    @Override
    public void connect(final int connectTimeout)
            throws GeneralSecurityException, IOException, SshChannelException {

        this.connectTimeout = connectTimeout;
        try {
            sendChannelOpen();
            onAfterConnect(session);

        } catch (final SshChannelException | GeneralSecurityException | IOException e) {
            disconnect();
            throw e;
        }
    }

    /**
     * This method gets called during {@link #connect(int)} after the channel opened.
     * Override this method to define additional/specific behavior.
     *
     * @param session passed in as a convenience
     *
     * @throws SshChannelException if any errors occur
     */
    protected void onAfterConnect(@NonNull final SessionImpl session)
            throws SshChannelException, GeneralSecurityException, IOException {
    }

    @Override
    public int getId() {
        return id;
    }

    /**
     * Get the REMOTE channel id.
     *
     * @return remote channel id
     */
    protected int getRecipient() {
        return recipient;
    }

    /**
     * Set the REMOTE channel id and notify any/all watchers we got it.
     *
     * @param recipient to set
     */
    protected synchronized void setRecipient(final int recipient) {
        this.recipient = recipient;
        if (notifyMe > 0) {
            notifyAll();
        }
    }

    /**
     * Get the channel type
     *
     * @return the ssh standard name for this channel
     */
    @NonNull
    public String getType() {
        return type;
    }

    /**
     * Checks if we have already read all the data,
     * i.e. whether the remote sent an end-of-file notification for this channel.
     */
    @SuppressWarnings("unused")
    public boolean isRemoteEof() {
        return eofRemote;
    }

    public void setConnectTimeout(final int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    /**
     * Gets an InputStream for this channel.
     * <p>
     * All data arriving in {@link SshConstants#SSH_MSG_CHANNEL_DATA} messages
     * from the remote side can be read from this stream.
     * <p>
     * This method is a polling alternative to {@link #setOutputStream}.
     * It should be called before {@link #connect}.
     */
    @Override
    @NonNull
    public InputStream getInputStream()
            throws IOException {

        final int pipeSize = getDefaultInputBufferSize();
        final int maxPipeSize = getMaxInputBufferSize();
        final boolean resizable = pipeSize < maxPipeSize;

        final PipedInputStream pin = new MyPipedInputStream(pipeSize, maxPipeSize);
        setOutputStream(new PassiveOutputStream(pin, resizable));
        return pin;
    }

    /**
     * Gets an InputStream for extended data of this channel.
     * <p>
     * All data arriving in {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} messages
     * from the remote side can be read from this stream.
     * <p>
     * This method is a polling alternative to {@link #setExtOutputStream}.
     * It should be called before {@link #connect}.
     */
    @Override
    @NonNull
    public InputStream getExtInputStream()
            throws IOException {

        final int pipeSize = getDefaultInputBufferSize();
        final int maxPipeSize = getMaxInputBufferSize();
        final boolean resizable = pipeSize < maxPipeSize;

        final PipedInputStream pin = new MyPipedInputStream(pipeSize, maxPipeSize);
        setExtOutputStream(new PassiveOutputStream(pin, resizable));
        return pin;
    }

    /**
     * Sets the InputStream for this channel.
     * <p>
     * The channel will then read from this stream and forward the data
     * in {@link SshConstants#SSH_MSG_CHANNEL_DATA} to the remote side.
     * <p>
     * This method should be called before {@link #connect}.
     *
     * @param do_not_close if {@code true}, we do not close the stream
     *                     after usage.
     */
    @Override
    public void setInputStream(@NonNull final InputStream in,
                               final boolean do_not_close) {
        ioStreams.setInputStream(in, do_not_close);
    }

    /**
     * Gets an OutputStream for this channel.
     * <p>
     * All data written to this stream will be sent in
     * {@link SshConstants#SSH_MSG_CHANNEL_DATA} messages to the remote side.
     * <p>
     * This method is an alternative to {@link #setInputStream}.
     * It should be called before {@link #connect}.
     */
    @Override
    @NonNull
    public OutputStream getOutputStream() {

        final BaseChannel channel = this;
        return new OutputStream() {
            /** Temporary buffer for writing a single byte of data. */
            private final byte[] singleByte = new byte[1];
            private boolean streamClosed;

            @Nullable
            private Packet packet;
            /** Current length of data in stream ready to be sent/flushed. */
            private int dataLength;

            /**
             * Initializes the stream for sending output over channel.
             *
             * @throws IOException on failure
             */
            private synchronized void init()
                    throws IOException {
                // Protect against being called before remoteMaxPacketSize is set.
                if (remoteMaxPacketSize < (Packet.HEADER_LEN + CHANNEL_PACKET_HEADER_LEN
                        + Packet.SAFE_MARGIN)) {
                    throw new IOException("Init failed: remoteMaxPacketSize not set");
                }
                packet = new Packet(remoteMaxPacketSize);
            }

            @Override
            public void write(final int w)
                    throws IOException {
                singleByte[0] = (byte) w;
                write(singleByte, 0, 1);
            }

            /**
             * Write to the internal packet buffer.
             * Sending the data to the server is done when the stream is {@link #flush() flushed}
             */
            @Override
            public void write(@NonNull final byte[] buf,
                              final int offset,
                              int length)
                    throws IOException {
                if (packet == null) {
                    init();
                }

                if (streamClosed) {
                    throw new IOException(ERROR_STREAM_CLOSED);
                }

                int srcOffset = offset;
                while (length > 0) {
                    // start at the next free position
                    final int dstOffset = CHANNEL_PACKET_HEADER_LEN + dataLength + 1;
                    final int _len = Math.min(length,
                                              packet.data.length - dstOffset - Packet.SAFE_MARGIN);

                    if (_len <= 0) {
                        flush();
                    } else {
                        System.arraycopy(buf, srcOffset, packet.data, dstOffset, _len);
                        dataLength += _len;
                        srcOffset += _len;
                        length -= _len;
                    }
                }
            }

            @Override
            public void flush()
                    throws IOException {
                if (streamClosed) {
                    throw new IOException(ERROR_STREAM_CLOSED);
                }
                if (dataLength == 0) {
                    return;
                }
                //noinspection ConstantConditions
                packet.init(SshConstants.SSH_MSG_CHANNEL_DATA)
                      .putInt(recipient)
                      .putInt(dataLength)
                      // we already copied the actual data in #write
                      .moveWritePosition(dataLength);
                try {
                    synchronized (channel) {
                        final int _dataLength = dataLength;
                        dataLength = 0;
                        if (!channel.closePacketSend) {
                            channel.sendChannelDataPacket(packet, _dataLength);
                        }
                    }
                } catch (final Exception e) {
                    close();
                    throw new IOException(e);
                }
            }

            @Override
            public void close()
                    throws IOException {
                if (streamClosed) {
                    return;
                }

                if (dataLength > 0) {
                    flush();
                }
                channel.sendEOF();
                streamClosed = true;
            }
        };
    }

    /**
     * Sets the OutputStream for this channel.
     * <p>
     * All data arriving in {@link SshConstants#SSH_MSG_CHANNEL_DATA} messages
     * from the remote side will be written to this OutputStream.
     * This method should be called before {@link #connect}.
     *
     * @param do_not_close set to {@code true}, to keep the stream open when the channel
     *                     is disconnected. i.e. the stream is under 'caller' control.
     *
     * @see #getInputStream
     */
    @Override
    public void setOutputStream(@NonNull final OutputStream out,
                                final boolean do_not_close) {
        ioStreams.setOutputStream(out, do_not_close);
    }

    /**
     * Sets the OutputStream for extended data for this channel.
     * All data arriving in {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} messages
     * from the remote side will be written to this OutputStream.
     * This method should be called before {@link #connect}.
     * <p>
     * <em>Note:</em> This implementation does not differentiate between
     * different 'data_type_code' values, as RFC 4254 only defines one type,
     * namely SSH_EXTENDED_DATA_STDERR.
     *
     * @param do_not_close set to {@code true}, to keep the stream open when the channel
     *                     is disconnected. i.e. the stream is under 'caller' control.
     *
     * @see #getExtInputStream
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-5.2">
     * RFC 4254 SSH Connection Protocol, section 5.2: Data Transfer</a>
     */
    @Override
    public void setExtOutputStream(@NonNull final OutputStream out,
                                   final boolean do_not_close) {
        ioStreams.setExtOutputStream(out, do_not_close);
    }

    protected int getDefaultInputBufferSize() {
        // this value should be customizable.
        return 32768;
    }

    private int getMaxInputBufferSize() {
        return session.getConfig()
                      .getIntValue(MAX_INPUT_BUFFER_SIZE, getDefaultInputBufferSize());
    }

    protected void startThread() {
        channelThread = new Thread(this::run);
        channelThread.setName(type + " thread " + session.getHost());
        if (session.isRunningAsDaemonThread()) {
            channelThread.setDaemon(true);
        }
        channelThread.start();
    }

    /**
     * Overridden by subclasses which need to do special processing of channel data.
     */
    protected void run() {
    }

    /**
     * Get data from the input stream, pack it up and send it using the session.
     * <p>
     * Runs in a loop until disconnected. Cleans up afterwards.
     * <p>
     * This method is called from {@link #run()} when appropriate.
     */
    protected void runDataTransferLoop() {
        final Packet packet = new Packet(remoteMaxPacketSize);
        final int bytesToRead = remoteMaxPacketSize
                - (Packet.HEADER_LEN + CHANNEL_PACKET_HEADER_LEN + 1
                + Packet.SAFE_MARGIN);
        int dataLength;
        try {
            while (isConnected() && channelThread != null && ioStreams.hasInputStream()) {
                // read the data directly to the proper location in the packet
                dataLength = ioStreams.read(packet.data, CHANNEL_PACKET_HEADER_LEN + 1,
                                            bytesToRead);

                if (dataLength == -1) {
                    sendEOF();
                    break;
                }

                // Complete the packet with the header,
                // and set the write offset behind the payload ready to send.
                packet.init(SshConstants.SSH_MSG_CHANNEL_DATA)
                      .putInt(recipient)
                      .putInt(dataLength)
                      .moveWritePosition(dataLength);

                synchronized (this) {
                    if (isConnected()) {
                        sendChannelDataPacket(packet, dataLength);
                    }

                }
            }
        } catch (final Exception e) {
            if (session.getLogger().isEnabled(Logger.ERROR)) {
                session.getLogger().log(Logger.ERROR, e, () -> "");
            }
        }

        disconnect();
    }

    /**
     * Called by the main Session loop with the
     * {@link SshConstants#SSH_MSG_CHANNEL_DATA} payload data.
     *
     * @param bytes  the (full) Packet containing the payload
     * @param offset start pointer into the bytes array for the payload data
     * @param length of the payload
     */
    protected void writeData(@NonNull final byte[] bytes,
                             final int offset,
                             final int length)
            throws IOException, SshChannelException, GeneralSecurityException {
        ioStreams.write(bytes, offset, length);
    }

    /**
     * Called by the main Session loop with the
     * {@link SshConstants#SSH_MSG_CHANNEL_EXTENDED_DATA} payload data.
     *
     * @param bytes  the (full) Packet containing the payload
     * @param offset start pointer into the bytes array for the payload data
     * @param length of the payload
     *
     * @throws SshChannelException is not thrown for now, but added to be consistent
     *                             with {@link #writeData(byte[], int, int)}
     */
    private void writeExtData(@NonNull final byte[] bytes,
                              final int offset,
                              final int length)
            throws IOException, SshChannelException {
        ioStreams.writeExt(bytes, offset, length);
    }

    /**
     * Returns the {@code Session} instance this channel is opened on.
     *
     * @return session instance
     */
    @NonNull
    public Session getSession() {
        return session;
    }

    /**
     * Send a data packet.
     * <p>
     * byte      SSH_MSG_CHANNEL_DATA
     * uint32    recipient channel
     * string    data (uint32 with the length followed by the data blob)
     *
     * @param packet     to send
     * @param dataLength the length of the 'data' blob
     */
    protected void sendChannelDataPacket(@NonNull final Packet packet,
                                         int dataLength)
            throws SshChannelException, IOException, GeneralSecurityException {

        while (true) {
            session.waitForKexExchange();

            synchronized (this) {
                if (remoteWindowSize < dataLength) {
                    try {
                        notifyMe++;
                        wait(100);

                    } catch (final InterruptedException ignore) {
                    } finally {
                        notifyMe--;
                    }
                }

                if (session.isInKeyExchange()) {
                    continue;
                }

                // enough space? break out of the 'while(true)' loop and send the packet
                if (remoteWindowSize >= dataLength) {
                    remoteWindowSize -= dataLength;
                    break;
                }
            }

            if (!isConnected()) {
                throw new SshChannelException("channel is closed");
            }

            // used to leave the synchronized block before actually sending the packet
            boolean sendNow = false;

            int offset = 0;
            byte command = 0;

            //TODO: the logic used here is rather confusing....
            synchronized (this) {
                if (remoteWindowSize > 0) {
                    // remoteWindowSize is a UINT32 hence can theoretically can be up to 4gb.
                    // We're assuming here that 2gb is the real-life maximum
                    // (and that size would be ridiculous...)
                    int len = (int) remoteWindowSize;
                    if (len > dataLength) {
                        len = dataLength;
                    }

                    if (len != dataLength) {
                        offset = shift(packet, len);
                    }
                    command = packet.getCommand();

                    dataLength -= len;
                    remoteWindowSize -= len;

                    sendNow = true;
                }
            }

            if (sendNow) {
                session.getTransportC2s()
                       .write(packet);
                // All done?
                if (dataLength == 0) {
                    return;
                }
                unshift(packet, command, offset, dataLength);
            }

            synchronized (this) {
                if (!session.isInKeyExchange()) {
                    // enough space? break out of the 'while(true)' loop and send the packet
                    if (remoteWindowSize >= dataLength) {
                        remoteWindowSize -= dataLength;
                        break;
                    }
                }
            }
        }

        // we get here when the remote window size is big enough and we can just send it.
        session.getTransportC2s()
               .write(packet);
    }

    protected void sendPacket(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {
        session.getTransportC2s()
               .write(packet);
    }

    /**
     * byte      SSH_MSG_CHANNEL_DATA
     * uint32    recipient channel
     * string    data (uint32 with the length followed by the data blob)
     *
     * @return the 'offset' which should be passed to
     * {@link #unshift(Packet packet, byte command, int offset, int dataLength)}
     */
    private int shift(@NonNull final Packet packet,
                      final int dataLength) {

        final int srcPos = 1 + CHANNEL_PACKET_HEADER_LEN + dataLength;

        final Transport transport = session.getTransportC2s();
        final int blockSize;
        final int macBlockSize;

        if (transport.cipher == null) {
            blockSize = 8;
            macBlockSize = 0;
        } else {
            blockSize = transport.cipher.getBlockSize();
            macBlockSize = transport.mac != null ? transport.mac.getDigestLength() : 0;
        }

        int paddingLength = (-srcPos) & (blockSize - 1);
        if (paddingLength < blockSize) {
            paddingLength += blockSize;
        }

        //TODO: we CANNOT enlarge the packet! It's a fixed size!!
        // enlarge the packet if needed

        final int needed = paddingLength + macBlockSize;
        packet.ensureCapacity(needed);

        final int destPos = srcPos + needed;

        System.arraycopy(packet.data, srcPos,
                         packet.data, destPos,
                         packet.writeOffset - srcPos);


        // command is position 5, followed by an int32 (4 bytes) for the recipient.
        // add 1 to move to the next byte and put the length
        // i.e.: Packet.PAYLOAD_START + 4 + 1 => 10
        packet.setWriteOffSet(10);
        packet.putInt(dataLength);
        packet.moveWritePosition(dataLength);

        return destPos;
    }

    /**
     * Move the channel data blob creating space before it for storing
     * the packet header, recipient and data-length.
     */
    private void unshift(@NonNull final Packet packet,
                         final byte command,
                         final int offset,
                         final int dataLength) {
        // create space
        System.arraycopy(packet.data, offset,
                         packet.data, CHANNEL_PACKET_HEADER_LEN + 1,
                         dataLength);
        // and reconstruct the channel data header.
        packet.init(command)
              .putInt(recipient)
              .putInt(dataLength)
              .moveWritePosition(dataLength);
    }

    /**
     * Called by the session when the remote end signals an end-of-file.
     * <p>
     * We note this status and close the output stream to the application side.
     */
    public void eofFromRemote() {
        eofRemote = true;
        ioStreams.closeOutputStream();
    }

    /**
     * Sends an EOF (end of file) message for the local stream and sets the
     * state as EOF locally.
     */
    protected void sendEOF() {
        if (eofLocal) {
            return;
        }
        eofLocal = true;

        try {
            synchronized (this) {
                if (recipient != NO_RECIPIENT && !closePacketSend) {
                    final Packet packet = new Packet(SshConstants.SSH_MSG_CHANNEL_EOF)
                            .putInt(recipient);
                    session.write(packet);
                }
            }
        } catch (final Exception ignore) {
        }
    }

    /**
     * Check if session and channel are fully connected to the remote
     *
     * @return {@code true} if session and channel are connected and a close is not in progress
     */
    public boolean isConnected() {
        return session.isConnected() && connected && !closePacketSend;
    }

    private void adjustWindowSize(final int size)
            throws IOException, GeneralSecurityException {

        localWindowSize -= size;

        if (localWindowSize < maxLocalWindowSize / 2) {
            final Packet packet = new Packet(SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST)
                    .putInt(recipient)
                    // uint32    bytes to add
                    .putInt(maxLocalWindowSize - localWindowSize);
            synchronized (this) {
                if (session.isConnected()) {
                    session.write(packet);
                }
            }
            localWindowSize = maxLocalWindowSize;
        }
    }

    /**
     * Overridden by some channels which will append more data.
     *
     * @return the basic open packet
     */
    @NonNull
    protected Packet createChannelOpenPacket() {
        // byte   SSH_MSG_CHANNEL_OPEN(90)
        // string channel type
        // uint32 sender channel
        // uint32 initial window size
        // uint32 maximum packet size
        return new Packet(SshConstants.SSH_MSG_CHANNEL_OPEN)
                .putString(type)
                .putInt(id)
                .putInt(localWindowSize)
                .putInt(localMaxPacketSize);
    }

    /**
     * Open a channel to the remote.
     */
    protected void sendChannelOpen()
            throws IOException, GeneralSecurityException, SshChannelOpenException {

        final Packet packet = createChannelOpenPacket();
        session.write(packet);

        // Now wait for the connection confirmation in the main transfer loop
        // which will notify us
        final long startTime = System.currentTimeMillis();
        final long timeout = connectTimeout;
        final long waitTime = timeout == 0L ? 10L : timeout;

        // if there is no timeout set, we'll loop up to 2000 times and then give up...
        int retry = timeout != 0L ? 1 : 2000;

        synchronized (this) {
            while (recipient == NO_RECIPIENT
                    && session.isConnected()
                    && retry > 0
                    && (timeout <= 0L || (System.currentTimeMillis() - startTime) <= timeout)
            ) {
                try {
                    notifyMe = 1;
                    wait(waitTime);
                } catch (final InterruptedException ignore) {
                } finally {
                    notifyMe = 0;
                }
                retry--;
            }
        }

        if (!session.isConnected()) {
            throw new SshChannelOpenException(0, ERROR_SESSION_NOT_CONNECTED);
        } else if (recipient == NO_RECIPIENT) {
            throw new SshChannelOpenException(openFailureCode, openFailureMessage);
        } else if (!openConfirmationReceived) {
            throw new SshChannelOpenException(0, "Channel failed to open (no open-confirmation)");
        }
        connected = true;
    }

    /**
     * Send a {@link SshConstants#SSH_MSG_CHANNEL_REQUEST} and optionally wait for a reply.
     *
     * @param request     to send
     * @param replyWanted flag: does the request want us to wait for a reply?
     */
    @SuppressWarnings("WeakerAccess")
    public void sendRequest(@NonNull final Request request,
                            final boolean replyWanted)
            throws GeneralSecurityException, IOException, SshChannelException {

        final Packet packet = request.create(getRecipient(), replyWanted);

        if (replyWanted) {
            this.reply = ReplyStatus.Waiting;
        }

        session.write(packet);

        if (replyWanted) {
            final long start = System.currentTimeMillis();
            while (isConnected() && reply == ReplyStatus.Waiting) {
                try {
                    Thread.sleep(10);
                } catch (final Exception ignore) {
                }
                if (connectTimeout > 0L && (System.currentTimeMillis() - start) > connectTimeout) {
                    this.reply = ReplyStatus.Failed;
                    throw new SshChannelException("channel request timeout");
                }
            }

            if (reply == ReplyStatus.Failed) {
                throw new SshChannelException("failed to send channel request");
            }
        }
    }

    /**
     * Handle an incoming command/packet meant for this channel.
     *
     * @param packet to handle
     */
    @Override
    public void handle(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {
        switch (packet.getCommand()) {
            case SshConstants.SSH_MSG_CHANNEL_DATA: {
                final int payloadLen = packet.getInt();
                if (payloadLen > 0) {
                    final int payloadStart = packet.getReadOffSet();
                    packet.skip(payloadLen);
                    try {
                        writeData(packet.data, payloadStart, payloadLen);
                        adjustWindowSize(payloadLen);
                    } catch (final IOException | SshChannelException e) {
                        disconnect();
                    }
                }
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_EXTENDED_DATA: {
                // data_type_code == 1 == SSH_EXTENDED_DATA_STDERR
                packet.getInt();
                final int payloadLen = packet.getInt();
                if (payloadLen > 0) {
                    final int payloadStart = packet.getReadOffSet();
                    packet.skip(payloadLen);
                    try {
                        writeExtData(packet.data, payloadStart, payloadLen);
                        adjustWindowSize(payloadLen);
                    } catch (final IOException | SshChannelException e) {
                        disconnect();
                    }
                }
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_REQUEST: {
                // Packet.PAYLOAD_START(5) + command(1) + recipient(4) == 10
                packet.setReadOffSet(10);
                // ignore/reject all
                packet.getJString(); // requestType
                final boolean wantReply = packet.getBoolean();
                if (wantReply) {
                    // re-use the packet
                    packet.init(SshConstants.SSH_MSG_CHANNEL_FAILURE)
                          .putInt(getRecipient());
                    session.write(packet);
                }
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
                setRecipient(packet.getInt());
                remoteWindowSize = packet.getUInt();
                remoteMaxPacketSize = packet.getInt();
                openConfirmationReceived = true;
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_OPEN_FAILURE: {
                openFailureCode = packet.getInt();
                openFailureMessage = packet.getJString();
                packet.skipString(/* language_tag */);
                disconnect();
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_WINDOW_ADJUST: {
                final long bytesToAdd = packet.getUInt();
                synchronized (this) {
                    this.remoteWindowSize += bytesToAdd;
                    if (notifyMe > 0) {
                        notifyAll();
                    }
                }
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_EOF: {
                eofFromRemote();
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_SUCCESS: {
                reply = ReplyStatus.Success;
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_FAILURE: {
                reply = ReplyStatus.Failed;
                break;
            }
            case SshConstants.SSH_MSG_CHANNEL_CLOSE: {
                disconnect();
                break;
            }
            default: {
                throw new IOException("Unexpected SSH message: " + packet.getCommand());
            }
        }
    }


    /**
     * Disconnects the channel from the SSH server and cleans up any open resources.
     * Calling this method when the channel is not connected has no effect.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-5.3">
     * RFC 4254 SSH Connection Protocol, section 5.3. Closing a Channel</a>
     */
    @Override
    public void disconnect() {
        try {
            if (connected && !closePacketSend && recipient != NO_RECIPIENT) {
                final Packet packet = new Packet(SshConstants.SSH_MSG_CHANNEL_CLOSE)
                        .putInt(recipient);
                try {
                    synchronized (this) {
                        session.write(packet);
                    }
                } catch (final Exception ignore) {
                }
            }

            connected = false;
            // whether we did send one or not is irrelevant.
            // But we need to be consistent with 'connected'
            closePacketSend = true;
            eofRemote = true;
            eofLocal = true;
            channelThread = null;

            ioStreams.close();

        } catch (final Exception ignore) {

        } finally {
            // Lastly, remove the channel from the channel pool.
            session.unregisterChannel(this);
        }
    }

    /**
     * The "want reply" reply status.
     */
    private enum ReplyStatus {
        /**
         * No request send yet, or no reply wanted.
         */
        None,
        /**
         * A request was send and we're waiting for the reply.
         */
        Waiting,
        /**
         * The request succeeded.
         */
        Success,
        /**
         * The request failed.
         */
        Failed
    }

    /**
     * Represents a {@link SshConstants#SSH_MSG_CHANNEL_REQUEST} to be sent to the remote side.
     */
    public interface Request {

        @NonNull
        Packet create(final int recipient,
                      final boolean wantReply)
                throws NoSuchAlgorithmException;
    }
}
