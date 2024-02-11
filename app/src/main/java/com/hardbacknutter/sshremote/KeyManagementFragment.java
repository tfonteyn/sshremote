package com.hardbacknutter.sshremote;

import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.MenuProvider;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.snackbar.Snackbar;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import com.hardbacknutter.sshremote.databinding.FragmentKeyManagementBinding;
import com.hardbacknutter.sshremote.databinding.RowSshKeyBinding;
import com.hardbacknutter.sshremote.ddsupport.ItemTouchHelperAdapter;
import com.hardbacknutter.sshremote.ddsupport.SimpleItemTouchHelperCallback;
import com.hardbacknutter.sshremote.ssh.SshHelper;

public class KeyManagementFragment
        extends BaseFragment {

    static final String TAG = "KeyManagementFragment";

    private static final String MIME_TYPES = "*/*";

    private FragmentKeyManagementBinding vb;
    private KeyManagementViewModel vm;

    /**
     * The launcher for picking a Uri to write to.
     */
    private final ActivityResultLauncher<String> createDocumentLauncher =
            registerForActivityResult(new ActivityResultContracts.CreateDocument("*/*"),
                                      this::exportToUri);
    private HostKeyAdapter adapter;
    /**
     * The launcher for picking a Uri to read from.
     */
    private final ActivityResultLauncher<String> openUriLauncher =
            registerForActivityResult(new ActivityResultContracts.GetContent(), this::onOpenUri);
    @SuppressWarnings("FieldCanBeLocal")
    private ItemTouchHelper itemTouchHelper;

    @Nullable
    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        vb = FragmentKeyManagementBinding.inflate(inflater, container, false);
        return vb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        vm = new ViewModelProvider(this).get(KeyManagementViewModel.class);
        vm.init(context);

        adapter = new HostKeyAdapter(context);
        vb.keyList.setAdapter(adapter);
        vb.keyList.addItemDecoration(
                new DividerItemDecoration(context, DividerItemDecoration.HORIZONTAL));

        final SimpleItemTouchHelperCallback sitHelperCallback =
                new SimpleItemTouchHelperCallback(adapter);
        sitHelperCallback.setItemViewSwipeEnabled(true);
        itemTouchHelper = new ItemTouchHelper(sitHelperCallback);
        itemTouchHelper.attachToRecyclerView(vb.keyList);

        final Toolbar toolbar = initToolbar(new ToolbarMenuProvider());
        toolbar.setSubtitle(R.string.lbl_key_management);
    }

    @SuppressLint("NotifyDataSetChanged")
    private void onOpenUri(@Nullable final Uri uri) {
        if (uri != null) {
            try {
                //noinspection ConstantConditions
                vm.startImport(getContext(), uri);
                adapter.notifyDataSetChanged();
            } catch (final IOException | NoSuchAlgorithmException e) {
                Snackbar.make(vb.getRoot(), R.string.error_import_failed, Snackbar.LENGTH_LONG)
                        .show();
            }
        }
    }

    private void exportToUri(@Nullable final Uri uri) {
        if (uri != null) {
            try {
                //noinspection ConstantConditions
                vm.startExport(getContext(), uri);
            } catch (final IOException e) {
                Snackbar.make(vb.getRoot(), R.string.error_export_failed, Snackbar.LENGTH_LONG)
                        .show();
            }
        }
    }

    public static class Holder
            extends RecyclerView.ViewHolder {

        @NonNull
        private final RowSshKeyBinding vb;

        Holder(@NonNull final View itemView) {
            super(itemView);
            vb = RowSshKeyBinding.bind(itemView);
        }
    }

    public class HostKeyAdapter
            extends RecyclerView.Adapter<Holder>
            implements ItemTouchHelperAdapter {

        @NonNull
        private final LayoutInflater layoutInflater;

        HostKeyAdapter(@NonNull final Context context) {
            layoutInflater = LayoutInflater.from(context);
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull final ViewGroup parent,
                                         final int viewType) {
            final View view = layoutInflater.inflate(R.layout.row_ssh_key, parent, false);
            return new Holder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull final Holder holder,
                                     final int position) {
            final KeyManagementViewModel.HostLine line = vm.getHostList().get(position);

            holder.vb.host.setText(line.host);
            holder.vb.type.setText(line.type);
            holder.vb.fingerprint.setText(line.fingerprint);
        }

        @Override
        public int getItemCount() {
            return vm.getHostList().size();
        }

        @Override
        public void onItemSwiped(final int position) {
            vm.getHostList().remove(position);
            notifyItemRemoved(position);
        }
    }

    private class ToolbarMenuProvider implements MenuProvider {

        @Override
        public void onCreateMenu(@NonNull final Menu menu,
                                 @NonNull final MenuInflater menuInflater) {
            menuInflater.inflate(R.menu.menu_key_management, menu);
        }

        @Override
        public boolean onMenuItemSelected(@NonNull final MenuItem menuItem) {
            final int itemId = menuItem.getItemId();

            if (itemId == R.id.MENU_SAVE) {
                try {
                    //noinspection ConstantConditions
                    vm.save(getContext());
                    getParentFragmentManager().popBackStack();
                } catch (final IOException e) {
                    Snackbar.make(vb.getRoot(), R.string.error_save_failed, Snackbar.LENGTH_LONG)
                            .show();
                }
                return true;

            } else if (itemId == R.id.MENU_IMPORT) {
                vm.setImportIsAppend(false);
                openUriLauncher.launch(MIME_TYPES);
                return true;

            } else if (itemId == R.id.MENU_IMPORT_APPEND) {
                vm.setImportIsAppend(true);
                openUriLauncher.launch(MIME_TYPES);
                return true;

            } else if (itemId == R.id.MENU_EXPORT) {
                createDocumentLauncher.launch(SshHelper.KNOWN_HOSTS);
            }
            return false;
        }
    }
}
