package com.hardbackcollector.sshremote;

import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.fragment.app.Fragment;

import java.util.Objects;

public abstract class BaseFragment extends Fragment {

    private Toolbar toolbar;

    @NonNull
    protected Toolbar getToolbar() {
        if (toolbar == null) {
            //noinspection ConstantConditions
            toolbar = Objects.requireNonNull(getActivity().findViewById(R.id.toolbar),
                                             "R.id.toolbar");
        }
        return toolbar;
    }
}
