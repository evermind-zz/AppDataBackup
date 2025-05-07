package com.github.evermindzz.appdatabackup;

import android.app.ProgressDialog;
import android.content.Context;
import android.net.Uri;
import android.os.AsyncTask;

import java.io.File;
import java.util.regex.Pattern;

public class BackupUtilsAsync {
    private static final String TAG = "BackupUtilsAsync";

    // Create tarball asynchronously
    public static void createTarballAsync(Context context, String password, BackupUtils.EncryptionMode encryptionMode,
                                          Pattern fileFilter, boolean createLogFile, File workingDir, BackupCallback callback) {
        new AsyncTask<Void, Integer, File>() {
            private final BackupUtils backupUtils = new BackupUtils(context, workingDir);
            private Exception error;
            private ProgressDialog progressDialog;

            @Override
            protected void onPreExecute() {
                progressDialog = new ProgressDialog(context);
                progressDialog.setMessage("Creating backup...");
                progressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
                progressDialog.setCancelable(false);
                progressDialog.show();

                backupUtils.enableFileLogging(context, createLogFile);
            }

            @Override
            protected File doInBackground(Void... voids) {
                try {
                    return backupUtils.createTarball(context, password, encryptionMode, fileFilter, this::publishProgress, null);
                } catch (Exception e) {
                    this.error = e;
                    return null;
                }
            }

            @Override
            protected void onProgressUpdate(Integer... values) {
                progressDialog.setProgress(values[0]);
            }

            @Override
            protected void onPostExecute(File tarballFile) {
                progressDialog.dismiss();
                callback.onBackupComplete(tarballFile, error);
            }
        }.execute();
    }

    // Restore tarball asynchronously
    public static void restoreTarballAsync(Context activity, Uri tarballUri, String password,
                                           BackupUtils.EncryptionMode encryptionMode, boolean eraseBeforeRestore,
                                           boolean restorePermissions, boolean restoreTimestamps,
                                           File workingDir, BackupCallback callback) {
        new AsyncTask<Void, Integer, Void>() {
            private final BackupUtils backupUtils = new BackupUtils(activity, workingDir);
            private Exception error;
            private ProgressDialog progressDialog;

            @Override
            protected void onPreExecute() {
                progressDialog = new ProgressDialog(activity);
                progressDialog.setMessage("Restoring backup...");
                progressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
                progressDialog.setCancelable(false);
                progressDialog.show();
            }

            @Override
            protected Void doInBackground(Void... voids) {
                try {
                    backupUtils.restoreTarball(activity, tarballUri, password, encryptionMode,
                            eraseBeforeRestore, restorePermissions, restoreTimestamps, this::publishProgress);
                } catch (Exception e) {
                    this.error = e;
                }
                return null;
            }

            @Override
            protected void onProgressUpdate(Integer... values) {
                progressDialog.setProgress(values[0]);
            }

            @Override
            protected void onPostExecute(Void result) {
                progressDialog.dismiss();
                callback.onRestoreComplete(error);
            }
        }.execute();
    }

    // Callback interface for async operations
    public interface BackupCallback {
        void onBackupComplete(File tarballFile, Exception error);

        void onRestoreComplete(Exception error);
    }
}
