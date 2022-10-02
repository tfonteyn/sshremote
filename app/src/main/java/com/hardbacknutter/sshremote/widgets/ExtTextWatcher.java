package com.hardbacknutter.sshremote.widgets;

import android.text.TextWatcher;

import androidx.annotation.NonNull;

public interface ExtTextWatcher
        extends TextWatcher {

    @Override
    default void beforeTextChanged(@NonNull final CharSequence s,
                                   final int start,
                                   final int count,
                                   final int after) {
    }

    @Override
    default void onTextChanged(@NonNull final CharSequence s,
                               final int start,
                               final int before,
                               final int count) {
    }
}
