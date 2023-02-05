package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;

public class UnsupportedKeyBlobEncodingException extends IOException {

    private static final long serialVersionUID = -7252868695693101557L;

    public UnsupportedKeyBlobEncodingException(@Nullable final PrivateKeyEncoding format) {
        super(String.valueOf(format));
    }

    public UnsupportedKeyBlobEncodingException(@Nullable final PublicKeyEncoding format) {
        super(String.valueOf(format));
    }

    public UnsupportedKeyBlobEncodingException(@NonNull final String format) {
        super(format);
    }
}
