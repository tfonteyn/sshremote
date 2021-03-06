package com.hardbackcollector.sshremote;

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
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.NavController;
import androidx.navigation.fragment.NavHostFragment;

import com.hardbackcollector.sshremote.databinding.FragmentEditHostBinding;
import com.hardbackcollector.sshremote.db.Host;
import com.hardbackcollector.sshremote.widgets.ExtTextWatcher;

public class EditHostFragment
        extends Fragment {

    private FragmentEditHostBinding mVb;

    private EditHostViewModel mVm;

    private NavController mNavController;

    @Override
    public void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        mVb = FragmentEditHostBinding.inflate(inflater, container, false);
        return mVb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        mNavController = NavHostFragment.findNavController(this);

        mVm = new ViewModelProvider(this).get(EditHostViewModel.class);
        mVm.init(context, getArguments());
        mVm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);
    }

    private void onConfigLoaded(@NonNull final Host host) {
        mVb.hostLabel.setText(host.label);
        mVb.hostLabel.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setLabel(s.toString()));

        mVb.hostnameOrIp.setText(host.hostnameOrIp);
        mVb.hostnameOrIp.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setHost(s.toString().trim()));

        if (host.port == Host.DEFAULT_PORT) {
            mVb.port.setText("");
        } else {
            mVb.port.setText(String.valueOf(host.port));
        }
        mVb.port.addTextChangedListener((ExtTextWatcher) s -> {
            try {
                final String p = s.toString().trim();
                if (p.isEmpty()) {
                    mVm.setPort(Host.DEFAULT_PORT);
                } else {
                    mVm.setPort(Integer.parseInt(p));
                }
            } catch (@NonNull final NumberFormatException e) {
                mVm.setPort(Host.DEFAULT_PORT);
                mVb.port.setText(String.valueOf(Host.DEFAULT_PORT));
            }
        });

        mVb.userName.setText(host.userName);
        mVb.userName.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setUserName(s.toString().trim()));

        mVb.password.setText(host.userPassword);
        mVb.password.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setUserPassword(s.toString().trim()));
    }

    @Override
    public void onCreateOptionsMenu(@NonNull final Menu menu,
                                    @NonNull final MenuInflater inflater) {
        inflater.inflate(R.menu.menu_edit, menu);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull final MenuItem item) {
        final int itemId = item.getItemId();

        if (itemId == R.id.MENU_SAVE) {
            //noinspection ConstantConditions
            mVm.save(getActivity());
            mNavController.popBackStack();
            return true;

        } else if (itemId == R.id.MENU_DELETE) {
            //noinspection ConstantConditions
            mVm.delete(getActivity());
            mNavController.popBackStack();
            return true;
        }
        return false;
    }
}
