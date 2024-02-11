package com.hardbacknutter.sshremote;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.MenuProvider;
import androidx.lifecycle.ViewModelProvider;

import com.hardbacknutter.sshremote.databinding.FragmentEditHostBinding;
import com.hardbacknutter.sshremote.db.Host;
import com.hardbacknutter.sshremote.widgets.ExtTextWatcher;

public class EditHostFragment
        extends BaseFragment {

    static final String TAG = "EditHostFragment";
    private FragmentEditHostBinding vb;

    private EditHostViewModel vm;

    @Nullable
    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        vb = FragmentEditHostBinding.inflate(inflater, container, false);
        return vb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        vm = new ViewModelProvider(this).get(EditHostViewModel.class);
        vm.init(context, getArguments());
        vm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);

        final Toolbar toolbar = initToolbar(new ToolbarMenuProvider());
        toolbar.setSubtitle(R.string.lbl_edit_host);
    }

    private void onConfigLoaded(@NonNull final Host host) {
        vb.hostLabel.setText(host.label);
        vb.hostLabel.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setLabel(s.toString()));

        vb.hostnameOrIp.setText(host.hostnameOrIp);
        vb.hostnameOrIp.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setHost(s.toString().trim()));

        if (host.port == Host.DEFAULT_PORT) {
            vb.port.setText("");
        } else {
            vb.port.setText(String.valueOf(host.port));
        }
        vb.port.addTextChangedListener((ExtTextWatcher) s -> {
            try {
                final String p = s.toString().trim();
                if (p.isEmpty()) {
                    vm.setPort(Host.DEFAULT_PORT);
                } else {
                    vm.setPort(Integer.parseInt(p));
                }
            } catch (@NonNull final NumberFormatException e) {
                vm.setPort(Host.DEFAULT_PORT);
                vb.port.setText(String.valueOf(Host.DEFAULT_PORT));
            }
        });

        vb.userName.setText(host.userName);
        vb.userName.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setUserName(s.toString().trim()));

        vb.password.setText(host.userPassword);
        vb.password.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setUserPassword(s.toString().trim()));
    }

    private class ToolbarMenuProvider
            implements MenuProvider {

        @Override
        public void onCreateMenu(@NonNull final Menu menu,
                                 @NonNull final MenuInflater menuInflater) {
            menuInflater.inflate(R.menu.menu_edit, menu);
        }

        @Override
        public boolean onMenuItemSelected(@NonNull final MenuItem menuItem) {
            final int itemId = menuItem.getItemId();

            if (itemId == R.id.MENU_SAVE) {
                //noinspection ConstantConditions
                vm.save(getActivity());
                getParentFragmentManager().popBackStack();
                return true;

            } else if (itemId == R.id.MENU_DELETE) {
                //noinspection ConstantConditions
                vm.delete(getActivity());
                getParentFragmentManager().popBackStack();
                return true;
            }
            return false;
        }
    }

}
