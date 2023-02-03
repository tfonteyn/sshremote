package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import java.io.IOException;

public class UnsupportedKeyBlobEncodingException extends IOException {

    private static final long serialVersionUID = -7252868695693101557L;

    public UnsupportedKeyBlobEncodingException(@NonNull final String format) {
        super(format);
    }
}
