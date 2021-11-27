package com.hardbackcollector.sshclient.kex;

import java.io.IOException;

public class KexProtocolException
        extends IOException {

    private static final long serialVersionUID = 8335341823291550436L;
    private final byte expected;
    private final byte received;

    public KexProtocolException(final byte expected,
                                final byte received) {
        this.expected = expected;
        this.received = received;
    }

    public byte getExpected() {
        return expected;
    }

    public byte getReceived() {
        return received;
    }

    @Override
    public String getMessage() {
        return "Invalid protocol: expected=" + expected + ", received=" + received;
    }
}
