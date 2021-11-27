package com.hardbackcollector.sshremote;

import androidx.lifecycle.LiveData;

/**
 * Prevent acting twice on a delivered {@link LiveData} event.
 * <p>
 * See <a href="https://medium.com/androiddevelopers/livedata-with-snackbar-navigation-and-other-events-the-singleliveevent-case-ac2622673150">
 * this Medium post</a>
 * <p>
 * Modified from the article: the client must call {@link #isNewEvent()},
 * so we can pass {@code null} as valid data.
 * <p>
 * Example implementation:
 * <pre>
 *     {@code
 *          private boolean mHasBeenHandled;
 *
 *          public boolean isNewEvent() {
 *              boolean isNew = !mHasBeenHandled;
 *              mHasBeenHandled = true;
 *              return isNew;
 *          }
 *     }
 * </pre>
 */
public interface LiveDataEvent {

    /**
     * Check if the data needs handling, or can be ignored.
     *
     * @return {@code true} if this is a new event that needs handling.
     * {@code false} if the client can choose not to handle it.
     */
    boolean isNewEvent();
}
