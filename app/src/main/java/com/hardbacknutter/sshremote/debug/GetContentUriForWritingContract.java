package com.hardbacknutter.sshremote.debug;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;

import androidx.activity.result.contract.ActivityResultContract;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Optional;

/**
 * A replacement for
 * {@link androidx.activity.result.contract.ActivityResultContracts.CreateDocument}.
 * <p>
 * Allows us to set the mimeType properly, and use an Optional as the return type.
 */
public class GetContentUriForWritingContract
        extends ActivityResultContract<GetContentUriForWritingContract.Input, Optional<Uri>> {

    @NonNull
    @Override
    public Intent createIntent(@NonNull final Context context,
                               @NonNull final Input input) {
        return new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .setType(input.mimeType)
                .putExtra(Intent.EXTRA_TITLE, input.fileName);
    }

    @Override
    @NonNull
    public Optional<Uri> parseResult(final int resultCode,
                                     @Nullable final Intent intent) {
        if (intent == null || resultCode != Activity.RESULT_OK) {
            return Optional.empty();
        }

        final Uri uri = intent.getData();
        if (uri != null) {
            return Optional.of(uri);
        } else {
            return Optional.empty();
        }
    }

    public static class Input {

        @NonNull
        final String mimeType;
        @NonNull
        final String fileName;

        public Input(@NonNull final String mimeType,
                     @NonNull final String fileName) {
            this.mimeType = mimeType;
            this.fileName = fileName;
        }
    }
}
