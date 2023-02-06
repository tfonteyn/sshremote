package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;

@SuppressWarnings("WeakerAccess")
public class UnsupportedKeyBlobEncodingException extends IOException {

    private static final long serialVersionUID = 7073487457114722702L;

    UnsupportedKeyBlobEncodingException(@Nullable final PrivateKeyEncoding encoding) {
        super(String.valueOf(encoding));
    }

    UnsupportedKeyBlobEncodingException(@Nullable final PublicKeyEncoding encoding) {
        super(String.valueOf(encoding));
    }

    public UnsupportedKeyBlobEncodingException(@NonNull final String format) {
        super(format);
    }
}
