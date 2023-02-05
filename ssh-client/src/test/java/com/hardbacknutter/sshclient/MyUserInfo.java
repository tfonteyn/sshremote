package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.userauth.UserInfo;

import java.nio.charset.StandardCharsets;

public class MyUserInfo
        implements UserInfo {

    @Nullable
    private final String password;
    @Nullable
    private final String keyFilesPassphrase;

    public MyUserInfo(@Nullable final String password,
                      @Nullable final String keyFilesPassphrase) {

        this.password = password;
        this.keyFilesPassphrase = keyFilesPassphrase;
    }

    @Override
    public void showMessage(@NonNull final String message) {
        System.out.println("USER INFO showMessage: " + message);
    }

    @Override
    public boolean promptPassword(@NonNull final String message,
                                  @NonNull final String destination) {
        System.out.println("USER INFO promptPassword: " + String.format(message, destination));
        return password != null;
    }

    @Nullable
    @Override
    public byte[] getPassword() {
        //noinspection ConstantConditions
        return password.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public boolean promptPassphrase(@NonNull final String message,
                                    @NonNull final String destination) {
        System.out.println("USER INFO promptPassphrase: " + String.format(message, destination));
        return keyFilesPassphrase != null;
    }

    @Nullable
    @Override
    public byte[] getPassphrase() {
        //noinspection ConstantConditions
        return keyFilesPassphrase.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public boolean promptYesNo(final int reasonCode,
                               @NonNull final String message) {
        //     int RC_GENERIC = 0;
        //     int RC_CREATE_FILE = 1;
        //     int RC_CREATE_DIRECTORY = 2;
        //     int RC_REPLACE_KEY = 3;
        //     int RC_ACCEPT_NON_MATCHING_KEY = 4;
        System.out.println("USER INFO promptYesNo: " + reasonCode + ": " + message);
        return true;
    }
}
