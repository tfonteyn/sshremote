package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.userauth.UserInfo;

import java.nio.charset.StandardCharsets;

public class MyUserInfo
        implements UserInfo {

    private static final byte[] PASSWORD = "qwerty".getBytes(StandardCharsets.UTF_8);

    private boolean response = true;

    @Override
    public void showMessage(@NonNull final String message) {
        System.out.println("USER INFO showMessage: " + message);
    }

    @Override
    public boolean promptPassword(@NonNull final String message,
                                  @NonNull final String destination) {
        System.out.println("USER INFO promptPassword: " + String.format(message, destination));
        response = !response;
        System.out.println(response);
        return response;
    }

    @Nullable
    @Override
    public byte[] getPassword() {
        return PASSWORD;
    }

    @Override
    public boolean promptPassphrase(@NonNull final String message,
                                    @NonNull final String destination) {
        System.out.println("USER INFO promptPassphrase: " + String.format(message, destination));
        response = !response;
        System.out.println(response);
        return response;
    }

    @Nullable
    @Override
    public byte[] getPassphrase() {
        return PASSWORD;
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
        response = !response;
        System.out.println(response);
        return response;
    }
}
