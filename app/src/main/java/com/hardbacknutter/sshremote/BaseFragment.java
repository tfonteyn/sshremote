package com.hardbacknutter.sshremote;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;

public abstract class BaseFragment
        extends Fragment {

    private final OnBackPressedCallback backPressedCallback =
            new OnBackPressedCallback(true) {
                @Override
                public void handleOnBackPressed() {
                    getParentFragmentManager().popBackStack();
                }
            };

    @NonNull
    Toolbar initToolbar(@NonNull final MenuProvider toolbarMenuProvider) {
        final MainActivity activity = (MainActivity) getActivity();
        //noinspection DataFlowIssue
        final Toolbar toolbar = activity.getToolbar();
        toolbar.addMenuProvider(toolbarMenuProvider, getViewLifecycleOwner());
        toolbar.setNavigationIcon(R.drawable.arrow_back_24px);
        toolbar.setNavigationOnClickListener(v -> getParentFragmentManager().popBackStack());

        activity.getOnBackPressedDispatcher()
                .addCallback(getViewLifecycleOwner(), backPressedCallback);
        return toolbar;
    }
}
