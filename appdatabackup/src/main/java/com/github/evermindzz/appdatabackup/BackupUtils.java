package com.github.evermindzz.appdatabackup;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.net.Uri;

import com.github.evermindzz.osext.utils.NativeUtils;
import com.github.evermindzz.osext.utils.Stat;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for backing up and restoring application data directories.
 * Handles files, directories, and symlinks with optional encryption and logging.
 * Compatible with Android API 19 (4.4 KitKat).
 */
public class BackupUtils {
    // Constants for activity result codes
    public static final int REQUEST_CODE_SHARE_BACKUP = 100;
    public static final int REQUEST_CODE_RESTORE_BACKUP = 101;

    // Shared Pref to store temporary the last backup to be deleted after sharing is complete
    public static final String BACKUP_UTILS_SHARED_PREF = "backupUtilsPref";
    public static final String BACKUP_UTILS_LAST_TARBALL_PREF_KEY = "backupUtils_last_tarball_key";

    // Constant for minimum path parts in tarball entry (e.g., <applicationId>/databases/bookworm.db)
    private static final int MIN_TARBALL_PATH_PARTS = 2;

    // Constant for I/O buffer size (8KB for efficient reading/writing)
    private static final int BUFFER_SIZE = 8192;

    // AES encryption algorithm
    private static final String ENCRYPTION_ALGORITHM = "AES";

    // PBKDF2 settings for strong encryption
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int PBKDF2_KEY_LENGTH = 128; // 128-bit key for AES
    private static final int SALT_LENGTH = 16; // 16-byte salt

    // Metadata file names in outer tarball
    private static final String METADATA_FILE = ".backupUtils-metadata.stat";
    private static final String TOTAL_FILES_METADATA = ".backupUtils-metadata.total_files";
    private static final String DATA_TARBALL = "data.tar.gz"; // contains the backup'ed files
    private static final String LOG_FILE = "backup.log.gz";

    // Default modes
    private static final int DEFAULT_FILE_MODE = 0600;
    private static final int DEFAULT_DIR_MODE = 0755;
    private static final int DEFAULT_SYMLINK_MODE = 0777;

    // Database extensions for validation
    private static final Set<String> DATABASE_EXTENSIONS = new HashSet<String>() {{
        add(".db");
        add(".sqlite");
        add(".db3");
    }};
    private final String applicationId;
    private final String metadataPath;
    private final String totalFilesPath;
    private final String dataTarPath;
    private final String logPath;
    private final File workingDir;
    private File logFile = null;

    public BackupUtils(Context context, File workingDir) {
        this.applicationId = context.getPackageName();
        this.metadataPath = applicationId + "/" + METADATA_FILE;
        this.totalFilesPath = applicationId + "/" + TOTAL_FILES_METADATA;
        this.dataTarPath = applicationId + "/" + DATA_TARBALL;
        this.logPath = applicationId + "/" + LOG_FILE;
        this.workingDir = workingDir;

        if (this.workingDir == null) {
            new RuntimeException("the working dir should never be null. It is essential to get stuff done.");
        }
    }

    /**
     * Checks if a file is a valid SQLite database by reading its header.
     *
     * @param file The file to check.
     * @return true if the file is a valid SQLite database, false otherwise.
     */
    static boolean isValidSQLiteDatabase(File file) {
        if (!file.isFile() || !file.canRead()) {
            return false;
        }

        // Check file extension
        String name = file.getName().toLowerCase(Locale.US);
        boolean hasValidExtension = false;
        for (String ext : DATABASE_EXTENSIONS) {
            if (name.endsWith(ext)) {
                hasValidExtension = true;
                break;
            }
        }
        if (!hasValidExtension) {
            return false;
        }

        // Check SQLite header (first 16 bytes: "SQLite format 3\0")
        FileInputStream fis = null;
        BufferedInputStream in = null;
        try {
            fis = new FileInputStream(file);
            in = new BufferedInputStream(fis);
            byte[] header = new byte[16];
            int bytesRead = in.read(header);
            if (bytesRead != 16) {
                return false;
            }
            String headerStr = new String(header, "UTF-8");
            return "SQLite format 3\0".equals(headerStr);
        } catch (IOException e) {
            Logger.w("Failed to read SQLite header for " + file.getAbsolutePath() + ": " + e.getMessage());
            return false;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    Logger.w("Failed to close input stream for " + file.getAbsolutePath());
                }
            }
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    Logger.w("Failed to close file input stream for " + file.getAbsolutePath());
                }
            }
        }
    }

    /**
     * Share tarball via {@link CustomFileProvider}.
     */
    public static void shareTarball(Activity activity, String authority, File tarballFile) {
        try {
            Uri fileUri = CustomFileProvider.getUriForFile(activity, authority, tarballFile);
            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/x-tar");
            shareIntent.putExtra(Intent.EXTRA_STREAM, fileUri);
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            shareIntent.putExtra(Intent.EXTRA_TITLE, tarballFile.getName());
            activity.startActivityForResult(
                    Intent.createChooser(shareIntent, "Share backup"),
                    REQUEST_CODE_SHARE_BACKUP
            );
            getSharedBackupPref(activity)
                    .edit()
                    .putString(BACKUP_UTILS_LAST_TARBALL_PREF_KEY, tarballFile.getAbsolutePath())
                    .apply();
        } catch (Exception e) {
            Logger.e("Failed to share tarball", e);
        }
    }

    public static SharedPreferences getSharedBackupPref(Context context) {
        return context.getSharedPreferences(BACKUP_UTILS_SHARED_PREF, Context.MODE_PRIVATE);
    }

    /**
     * Start restore process.
     */
    public static void startRestore(Activity activity) {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        activity.startActivityForResult(intent, REQUEST_CODE_RESTORE_BACKUP);
    }

    /**
     * Enable or disable logging to a gzipped file.
     *
     * @param context   The application context.
     * @param doLogging If true, enables file logging.
     */
    public void enableFileLogging(Context context, boolean doLogging) {
        if (doLogging) {
            this.logFile = new File(workingDir, "backupUtils.log");
        } else {
            this.logFile = null;
        }
    }

    /**
     * Count regular files to back up based on filter.
     *
     * @param context    The application context.
     * @param fileFilter Regex pattern to filter files (null for all).
     * @return Number of files to back up.
     */
    public int countFiles(Context context, Pattern fileFilter) {
        File dataDir = new File(context.getApplicationInfo().dataDir); // /data/data/<package>/
        String tempTarball = new File(workingDir, DATA_TARBALL).getAbsolutePath();
        return countFilesRecursive(dataDir, fileFilter, tempTarball);
    }

    private int countFilesRecursive(File dir, Pattern fileFilter, String tempTarball) {
        if (!dir.exists() || !dir.isDirectory()) {
            return 0;
        }
        int totalFiles = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && !file.getAbsolutePath().equals(tempTarball)) {
                    String relativePath = getRelativePath(file, dir.getParentFile());
                    if (fileFilter == null || fileFilter.matcher(relativePath).matches()) {
                        totalFiles++;
                    }
                } else if (file.isDirectory()) {
                    totalFiles += countFilesRecursive(file, fileFilter, tempTarball);
                }
                // Symlinks are not counted for progress
            }
        }
        return totalFiles;
    }

    /**
     * Set up encryption for tarball output.
     *
     * @param fos            File output stream.
     * @param password       Encryption password (null for none).
     * @param encryptionMode Encryption mode (NONE, WEAK, STRONG).
     * @param salt           Salt for STRONG mode (output parameter).
     * @return Output stream (possibly encrypted).
     * @throws Exception If encryption setup fails.
     */
    public OutputStream setupEncryptionOutput(FileOutputStream fos, String password, EncryptionMode encryptionMode, byte[] salt) throws Exception {
        OutputStream out = fos;
        if (password != null && !password.isEmpty() && encryptionMode != EncryptionMode.NONE) {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec key;

            if (encryptionMode == EncryptionMode.STRONG) {
                // Generate random salt if not provided
                if (salt == null) {
                    salt = new byte[SALT_LENGTH];
                    new SecureRandom().nextBytes(salt);
                }

                // Derive key with PBKDF2
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                byte[] derivedKey = skf.generateSecret(spec).getEncoded();
                key = new SecretKeySpec(derivedKey, ENCRYPTION_ALGORITHM);
            } else {
                // Weak: Use password directly (padded/truncated to 16 bytes)
                byte[] passwordBytes = password.getBytes();
                byte[] keyBytes = new byte[16];
                System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, keyBytes.length));
                key = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
            }

            cipher.init(Cipher.ENCRYPT_MODE, key);
            out = new CipherOutputStream(fos, cipher);

            // Write salt for strong encryption
            if (encryptionMode == EncryptionMode.STRONG) {
                fos.write(salt);
            }
        }
        return out; // no encryption
    }

    /**
     * Set up decryption for tarball input.
     *
     * @param in             Input stream.
     * @param password       Decryption password (null for none).
     * @param encryptionMode Encryption mode (NONE, WEAK, STRONG).
     * @return Input stream (possibly decrypted).
     * @throws Exception If decryption setup fails.
     */
    public InputStream setupEncryptionInput(InputStream in, String password, EncryptionMode encryptionMode) throws Exception {
        if (password != null && !password.isEmpty() && encryptionMode != EncryptionMode.NONE) {
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            SecretKeySpec key;
            byte[] salt = null;

            if (encryptionMode == EncryptionMode.STRONG) {
                // Read salt from start of file
                salt = new byte[SALT_LENGTH];
                int bytesRead = in.read(salt);
                if (bytesRead != SALT_LENGTH) {
                    throw new Exception("Invalid salt length");
                }

                // Derive key with PBKDF2
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
                byte[] derivedKey = skf.generateSecret(spec).getEncoded();
                key = new SecretKeySpec(derivedKey, ENCRYPTION_ALGORITHM);
            } else {
                // Weak: Use password directly (padded/truncated to 16 bytes)
                byte[] passwordBytes = password.getBytes();
                byte[] keyBytes = new byte[16];
                System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, keyBytes.length));
                key = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
            }

            cipher.init(Cipher.DECRYPT_MODE, key);
            return new CipherInputStream(in, cipher);
        }
        return in; // no encryption
    }

    /**
     * Clean up stale backups based on retention policy.
     *
     * @param context The application context.
     * @param policy  The backup retention policy.
     */
    private void cleanStaleBackups(Context context, BackupRetentionPolicy policy) {
        File cacheDir = workingDir;
        String packageName = context.getPackageName().replace(".", "_");
        String backupPattern = packageName + "_[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}_backup\\.(tar|tar\\.enc)";
        Pattern pattern = Pattern.compile(backupPattern);

        // List all backup files
        File[] files = cacheDir.listFiles((dir, name) -> pattern.matcher(name).matches());
        if (files == null || files.length == 0) {
            Logger.d("No stale backups found in " + cacheDir.getAbsolutePath());
            return;
        }

        // Calculate cutoff time for retentionDays
        long currentTime = System.currentTimeMillis();
        long cutoffTime = policy.retentionDays > 0 ? currentTime - (policy.retentionDays * 24L * 60 * 60 * 1000) : Long.MAX_VALUE;

        // Collect files to delete
        List<File> backups = new ArrayList<>();
        for (File file : files) {
            if (file.isFile()) {
                backups.add(file);
            }
        }

        // Delete files older than retentionDays
        List<File> filesToDelete = new ArrayList<>();
        for (File file : backups) {
            if (file.lastModified() < cutoffTime) {
                filesToDelete.add(file);
            }
        }

        // If maxBackups is set, keep only the most recent maxBackups
        if (policy.maxBackups > 0 && backups.size() > policy.maxBackups) {
            // Sort by last modified time, newest first
            Collections.sort(backups, (f1, f2) -> Long.compare(f2.lastModified(), f1.lastModified()));
            // Add excess files to delete list
            for (int i = policy.maxBackups; i < backups.size(); i++) {
                if (!filesToDelete.contains(backups.get(i))) {
                    filesToDelete.add(backups.get(i));
                }
            }
        }

        // Delete stale files
        for (File file : filesToDelete) {
            if (file.delete()) {
                Logger.d("Deleted stale backup: " + file.getAbsolutePath());
            } else {
                Logger.w("Failed to delete stale backup: " + file.getAbsolutePath());
            }
        }

        Logger.d("Cleaned " + filesToDelete.size() + " stale backups from " + cacheDir.getAbsolutePath());
    }

    /**
     * Create tarball with nested structure.
     *
     * @param context          The application context.
     * @param password         Encryption password (null for none).
     * @param encryptionMode   Encryption mode (NONE, WEAK, STRONG).
     * @param fileFilter       Regex pattern to filter files and directories (null for all).
     * @param progressCallback Callback for progress updates.
     * @param retentionPolicy  Policy for removing stale backups (null for default: keep no existing backups).
     * @return The created tarball file.
     * @throws Exception If backup fails.
     */
    public File createTarball(Context context, String password, EncryptionMode encryptionMode, Pattern fileFilter,
                              ProgressCallback progressCallback, BackupRetentionPolicy retentionPolicy) throws Exception {
        // Initialize logging if enabled
        if (logFile != null) {
            Logger.setLogToFile(true, logFile);
            Logger.d("Starting backup creation");
        }

        // Use default retention policy if null
        BackupRetentionPolicy policy = retentionPolicy != null ? retentionPolicy : BackupRetentionPolicy.getDefault();

        // Clean stale backups before creating new one
        cleanStaleBackups(context, policy);

        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(new Date());
        String extension = (encryptionMode != EncryptionMode.NONE && password != null && !password.isEmpty()) ? "tar.enc" : "tar";
        String tarballName = applicationId.replace(".", "_") + "_" + timestamp + "_backup." + extension;
        File tarballFile = new File(workingDir, tarballName);

        Map<String, Stat> statMap = new HashMap<>();
        int totalFiles = countFiles(context, fileFilter); // Only regular files

        // Create inner data tarball (data.tar.gz)
        File dataTarball = new File(workingDir, DATA_TARBALL);
        FileOutputStream dataFos = null;
        GzipCompressorOutputStream dataGzipOut = null;
        TarArchiveOutputStream dataTarOut = null;
        try {
            dataFos = new FileOutputStream(dataTarball);
            dataGzipOut = new GzipCompressorOutputStream(dataFos);
            dataTarOut = new TarArchiveOutputStream(dataGzipOut);
            dataTarOut.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

            File dataDir = new File(context.getApplicationInfo().dataDir);
            String tempTarball = dataTarball.getAbsolutePath();
            int processedFiles = 0;
            writeDirRecursive(dataTarOut, dataDir, dataDir.getAbsolutePath(), fileFilter, statMap, tempTarball, progressCallback, totalFiles, new int[]{processedFiles});
            dataTarOut.finish();
        } finally {
            if (dataTarOut != null) {
                try {
                    dataTarOut.close();
                } catch (IOException e) {
                    Logger.w("Failed to close data tar output stream");
                }
            }
            if (dataGzipOut != null) {
                try {
                    dataGzipOut.close();
                } catch (IOException e) {
                    Logger.w("Failed to close gzip output stream");
                }
            }
            if (dataFos != null) {
                try {
                    dataFos.close();
                } catch (IOException e) {
                    Logger.w("Failed to close data file output stream");
                }
            }
        }

        // Create outer tarball (uncompressed) with metadata, log, and data.tar.gz
        FileOutputStream fos = null;
        OutputStream out = null;
        TarArchiveOutputStream tarOut = null;
        try {
            fos = new FileOutputStream(tarballFile);
            byte[] salt = new byte[SALT_LENGTH]; // Will be populated if STRONG encryption
            out = setupEncryptionOutput(fos, password, encryptionMode, salt);
            tarOut = new TarArchiveOutputStream(out);
            tarOut.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);

            // Write metadata first
            writeMetadata(tarOut, statMap, metadataPath);
            writeTotalFilesMetadata(tarOut, totalFiles);

            Logger.d(totalFiles + " files are stored in data.tar.gz");

            // Write log file if enabled
            if (logFile != null && logFile.exists()) {
                Logger.close(); // flush all data to disk so the logfile will not be corrupt
                TarArchiveEntry logEntry = new TarArchiveEntry(logFile, logPath);
                logEntry.setSize(logFile.length());
                logEntry.setMode(DEFAULT_FILE_MODE);
                tarOut.putArchiveEntry(logEntry);
                BufferedInputStream bis = null;
                try {
                    bis = new BufferedInputStream(new FileInputStream(logFile));
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = bis.read(buffer)) != -1) {
                        tarOut.write(buffer, 0, bytesRead);
                    }
                } finally {
                    if (bis != null) {
                        try {
                            bis.close();
                        } catch (IOException e) {
                            Logger.w("Failed to close log file input stream");
                        }
                    }
                }
                tarOut.closeArchiveEntry();
                Logger.d("Stored log file: " + logPath);
            }

            // Write data.tar.gz under applicationId/
            TarArchiveEntry dataEntry = new TarArchiveEntry(dataTarball, dataTarPath);
            dataEntry.setSize(dataTarball.length());
            dataEntry.setMode(DEFAULT_FILE_MODE);
            tarOut.putArchiveEntry(dataEntry);
            BufferedInputStream bis = null;
            try {
                bis = new BufferedInputStream(new FileInputStream(dataTarball));
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                while ((bytesRead = bis.read(buffer)) != -1) {
                    tarOut.write(buffer, 0, bytesRead);
                }
            } finally {
                if (bis != null) {
                    try {
                        bis.close();
                    } catch (IOException e) {
                        Logger.w("Failed to close data tar input stream");
                    }
                }
            }
            tarOut.closeArchiveEntry();

            tarOut.finish();
        } finally {
            if (tarOut != null) {
                try {
                    tarOut.close();
                } catch (IOException e) {
                    Logger.w("Failed to close tar output stream");
                }
            }
            if (out instanceof CipherOutputStream) {
                try {
                    out.close();
                } catch (IOException e) {
                    Logger.w("Failed to close cipher output stream");
                }
            }
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    Logger.w("Failed to close file output stream");
                }
            }
            if (dataTarball.exists()) {
                if (dataTarball.delete()) {
                    Logger.d("Deleted temporary data.tar.gz: " + dataTarball.getAbsolutePath());
                } else {
                    Logger.w("Failed to delete temporary data.tar.gz: " + dataTarball.getAbsolutePath());
                }
            }
            // Clean up log file
            if (logFile != null && logFile.exists()) {
                Logger.close();
                if (logFile.delete()) {
                    Logger.d("Deleted log file: " + logFile.getAbsolutePath());
                } else {
                    Logger.w("Failed to delete log file: " + logFile.getAbsolutePath());
                }
                logFile = null;
            }
        }

        return tarballFile;
    }

    /**
     * Recursively write directory contents to tarball, including directories only if they contain matching files
     * or match the filter themselves, including all contents of matched directories.
     */
    private void writeDirRecursive(TarArchiveOutputStream tarOut, File dir, String basePath, Pattern fileFilter,
                                   Map<String, Stat> statMap, String tempTarball, ProgressCallback progressCallback,
                                   int totalFiles, int[] processedFiles) throws Exception {
        if (!dir.exists() || !dir.isDirectory()) {
            return;
        }

        File baseDir = new File(basePath);
        String relativePath = getRelativePath(dir, baseDir);
        String tarPath = getTarEntryPath(relativePath);

        // Check if directory matches the filter
        boolean dirMatchesFilter = fileFilter != null && fileFilter.matcher(relativePath).matches();

        // Write directory entry if it's the root, matches the filter, contains matching files, or is under a matching directory
        boolean shouldWriteDir = dir.equals(baseDir) || dirMatchesFilter ||
                fileFilter == null || // Under a matching directory
                (fileFilter != null && hasMatchingFiles(dir, baseDir, fileFilter, tempTarball));
        if (shouldWriteDir) {
            TarArchiveEntry dirEntry = new TarArchiveEntry(dir, tarPath);
            Stat stat = null;
            try {
                stat = NativeUtils.getFileStat(dir.getAbsolutePath()); // Use stat64 for directories
                dirEntry.setMode(stat.st_mode & 0777);
                dirEntry.setUserId(stat.st_uid);
                dirEntry.setGroupId(stat.st_gid);
                dirEntry.setModTime(stat.st_mtime * 1000);
                statMap.put(tarPath, stat);
            } catch (IOException e) {
                dirEntry.setMode(DEFAULT_DIR_MODE);
                Logger.w("Failed to get stat for dir " + dir.getAbsolutePath() + ": " + e.getMessage());
            }
            tarOut.putArchiveEntry(dirEntry);
            tarOut.closeArchiveEntry();
            Logger.d("Stored directory: " + tarPath);
        }

        // Process contents
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.getAbsolutePath().equals(tempTarball)) {
                    continue; // Skip temporary data.tar.gz
                }
                String fileRelativePath = getRelativePath(file, baseDir);
                String fileTarPath = getTarEntryPath(fileRelativePath);

                if (file.isFile()) {
                    if (file.equals(logFile)) {
                        continue; // do not backup the logfile that resides within the backup directories
                    }
                    // Include file if no filter, directory matches filter, or file matches filter
                    if (fileFilter == null || dirMatchesFilter || fileFilter.matcher(fileRelativePath).matches()) {
                        writeTarEntry(tarOut, file, fileTarPath, statMap);
                        processedFiles[0]++;
                        if (progressCallback != null && totalFiles > 0) {
                            progressCallback.onProgress((processedFiles[0] * 100) / totalFiles);
                        }
                    }
                } else if (file.isDirectory()) {
                    // Pass dirMatchesFilter to subdirectories to include all their contents
                    writeDirRecursive(tarOut, file, basePath, dirMatchesFilter ? null : fileFilter,
                            statMap, tempTarball, progressCallback, totalFiles, processedFiles);
                } else {
                    try {
                        if (NativeUtils.isSymlink(file.getAbsolutePath())) {
                            // Include symlink if no filter or directory matches filter
                            if (fileFilter == null || dirMatchesFilter) {
                                writeSymlinkEntry(tarOut, file, fileTarPath, statMap);
                            }
                        }
                    } catch (IOException e) {
                        Logger.w("Failed to check if " + file.getAbsolutePath() + " is a symlink: " + e.getMessage());
                    }
                }
            }
        }
    }

    /**
     * Check if a directory contains files or subdirectories matching the filter, or matches the filter itself.
     */
    private boolean hasMatchingFiles(File dir, File baseDir, Pattern fileFilter, String tempTarball) {
        if (!dir.exists() || !dir.isDirectory()) {
            return false;
        }
        String relativePath = getRelativePath(dir, baseDir);
        // If directory matches the filter, include it and all contents
        if (fileFilter.matcher(relativePath).matches()) {
            return true;
        }
        File[] files = dir.listFiles();
        if (files == null) {
            return false;
        }
        for (File file : files) {
            if (file.getAbsolutePath().equals(tempTarball)) {
                continue;
            }
            if (file.isFile() && !file.equals(logFile)) {
                String fileRelativePath = getRelativePath(file, baseDir);
                if (fileFilter.matcher(fileRelativePath).matches()) {
                    return true;
                }
            } else if (file.isDirectory()) {
                if (hasMatchingFiles(file, baseDir, fileFilter, tempTarball)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Write a single file to tarball.
     */
    private void writeTarEntry(TarArchiveOutputStream tarOut, File file, String tarPath, Map<String, Stat> statMap) throws Exception {
        TarArchiveEntry entry = new TarArchiveEntry(file, tarPath);
        Stat stat = null;
        try {
            stat = NativeUtils.getFileStat(file.getAbsolutePath()); // Use stat64 for files
            entry.setMode(stat.st_mode & 0777);
            entry.setUserId(stat.st_uid);
            entry.setGroupId(stat.st_gid);
            entry.setSize(stat.st_size);
            entry.setModTime(stat.st_mtime * 1000);
            statMap.put(tarPath, stat);
            Logger.d("Storing file: " + tarPath + ", mode: " + Integer.toOctalString(stat.st_mode & 0777) +
                    ", uid: " + stat.st_uid + ", gid: " + stat.st_gid +
                    ", atime: " + stat.st_atime + "." + stat.st_atimeNsec +
                    ", mtime: " + stat.st_mtime + "." + stat.st_mtimeNsec);
        } catch (IOException e) {
            entry.setMode(DEFAULT_FILE_MODE);
            Logger.w("Failed to get stat for " + file.getAbsolutePath() + ": " + e.getMessage());
        }
        tarOut.putArchiveEntry(entry);

        BufferedInputStream bis = null;
        try {
            bis = new BufferedInputStream(new FileInputStream(file));
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = bis.read(buffer)) != -1) {
                tarOut.write(buffer, 0, bytesRead);
            }
        } finally {
            if (bis != null) {
                try {
                    bis.close();
                } catch (IOException e) {
                    Logger.w("Failed to close input stream for " + file.getAbsolutePath());
                }
            }
        }
        tarOut.closeArchiveEntry();
    }

    /**
     * Write a symlink to tarball.
     */
    private void writeSymlinkEntry(TarArchiveOutputStream tarOut, File file, String tarPath, Map<String, Stat> statMap) throws Exception {
        Stat stat = null;
        String linkTarget = null;
        try {
            stat = NativeUtils.getFileLstat(file.getAbsolutePath()); // Use lstat64 for symlinks
            linkTarget = stat.linkTarget;
        } catch (IOException e) {
            Logger.w("Failed to get lstat for symlink " + file.getAbsolutePath() + ": " + e.getMessage());
        }
        if (linkTarget == null) {
            // Fallback to File.getCanonicalPath()
            try {
                linkTarget = file.getCanonicalPath();
                Logger.d("Used File.getCanonicalPath() fallback for symlink: " + file.getAbsolutePath() + " -> " + linkTarget);
            } catch (IOException e) {
                Logger.w("Failed to read symlink target for " + file.getAbsolutePath() + " via native and canonical path: " + e.getMessage());
                return;
            }
        }
        if (linkTarget == null) {
            Logger.w("No valid symlink target for " + file.getAbsolutePath() + ", skipping");
            return;
        }
        TarArchiveEntry entry = new TarArchiveEntry(tarPath, TarArchiveEntry.LF_SYMLINK);
        entry.setLinkName(linkTarget);
        entry.setMode(stat != null ? (stat.st_mode & 0777) : DEFAULT_SYMLINK_MODE);
        entry.setUserId(stat != null ? stat.st_uid : 0);
        entry.setGroupId(stat != null ? stat.st_gid : 0);
        entry.setModTime(stat != null ? stat.st_mtime * 1000 : System.currentTimeMillis());
        statMap.put(tarPath, stat);
        tarOut.putArchiveEntry(entry);
        tarOut.closeArchiveEntry();
        Logger.d("Storing symlink: " + tarPath + " -> " + linkTarget);
    }

    /**
     * Write metadata to tarball.
     */
    private void writeMetadata(TarArchiveOutputStream tarOut, Map<String, Stat> statMap, String metadataPath) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = null;
        try {
            oos = new ObjectOutputStream(baos);
            oos.writeObject(statMap);
        } finally {
            if (oos != null) {
                try {
                    oos.close();
                } catch (IOException e) {
                    Logger.w("Failed to close object output stream");
                }
            }
        }
        byte[] statBytes = baos.toByteArray();
        TarArchiveEntry metaEntry = new TarArchiveEntry(metadataPath);
        metaEntry.setSize(statBytes.length);
        metaEntry.setMode(DEFAULT_FILE_MODE);
        tarOut.putArchiveEntry(metaEntry);
        tarOut.write(statBytes);
        tarOut.closeArchiveEntry();
        Logger.d("Stored " + metadataPath + " in tarball, size: " + statBytes.length + " bytes");
    }

    /**
     * Write total files metadata to tarball.
     */
    private void writeTotalFilesMetadata(TarArchiveOutputStream tarOut, int totalFiles) throws Exception {
        byte[] totalFilesBytes = String.valueOf(totalFiles).getBytes();
        TarArchiveEntry totalFilesEntry = new TarArchiveEntry(totalFilesPath);
        totalFilesEntry.setSize(totalFilesBytes.length);
        totalFilesEntry.setMode(DEFAULT_FILE_MODE);
        tarOut.putArchiveEntry(totalFilesEntry);
        tarOut.write(totalFilesBytes);
        tarOut.closeArchiveEntry();
        Logger.d("Stored " + totalFilesPath + " in tarball: " + totalFiles);
    }

    /**
     * Get tarball path for an entry.
     */
    private String getTarEntryPath(String relativePath) {
        return applicationId + (!relativePath.isEmpty() ? "/" + relativePath : "");
    }

    /**
     * Get relative path from file to base directory.
     */
    private String getRelativePath(File file, File baseDir) {
        String filePath = file.getAbsolutePath();
        String basePath = baseDir.getAbsolutePath();
        if (filePath.equals(basePath)) {
            return "";
        }
        if (filePath.startsWith(basePath + File.separator)) {
            return filePath.substring(basePath.length() + 1);
        }
        return file.getName();
    }

    /**
     * Restore tarball to /data/data/<package>/.
     *
     * @param context            The calling context.
     * @param tarballUri         URI of the tarball to restore.
     * @param password           Decryption password (null for none).
     * @param encryptionMode     Encryption mode (NONE, WEAK, STRONG).
     * @param eraseBeforeRestore Whether to erase existing files before restore.
     * @param restorePermissions Whether to restore file permissions.
     * @param restoreTimestamps  Whether to restore file timestamps.
     * @param progressCallback   Callback for progress updates.
     * @throws Exception If restore fails.
     */
    public void restoreTarball(Context context, Uri tarballUri, String password, EncryptionMode encryptionMode,
                               boolean eraseBeforeRestore, boolean restorePermissions, boolean restoreTimestamps,
                               ProgressCallback progressCallback) throws Exception {
        // Initialize logging if enabled
        if (logFile != null) {
            Logger.setLogToFile(true, logFile);
            Logger.d("Starting tarball restoration");
        }

        Map<String, Stat> statMap = null;
        int totalFiles = -1;
        File dataTarball = new File(workingDir, DATA_TARBALL);

        // Close databases
        Map<String, SQLiteDatabase> openDatabases = closeDatabases(context);

        // Extract outer tarball (uncompressed)
        InputStream in = null;
        TarArchiveInputStream outerTarIn = null;
        try {
            in = context.getContentResolver().openInputStream(tarballUri);
            if (in == null) {
                throw new Exception("Failed to open tarball URI");
            }
            in = setupEncryptionInput(in, password, encryptionMode);
            outerTarIn = new TarArchiveInputStream(in);
            TarArchiveEntry entry;
            boolean dataTarballExtracted = false;

            // verify, extract and prepare all required files for restore
            while ((entry = outerTarIn.getNextTarEntry()) != null) {
                if (!entry.isDirectory()) {
                    String entryName = entry.getName();
                    if (entryName.equals(metadataPath)) {
                        statMap = readMetadata(outerTarIn);
                        continue;
                    }
                    if (entryName.equals(totalFilesPath)) {
                        totalFiles = readTotalFilesMetadata(outerTarIn);
                        continue;
                    }
                    if (entryName.equals(logPath)) {
                        continue;
                    }
                    if (entryName.equals(dataTarPath)) {
                        BufferedOutputStream bos = null;
                        try {
                            bos = new BufferedOutputStream(new FileOutputStream(dataTarball));
                            byte[] buffer = new byte[BUFFER_SIZE];
                            int bytesRead;
                            while ((bytesRead = outerTarIn.read(buffer)) != -1) {
                                bos.write(buffer, 0, bytesRead);
                            }
                        } finally {
                            if (bos != null) {
                                try {
                                    bos.close();
                                } catch (IOException e) {
                                    Logger.w("Failed to close data tarball output stream");
                                }
                            }
                        }
                        dataTarballExtracted = true;
                        continue;
                    }
                    throw new Exception("Invalid tarball: unexpected entry " + entryName);
                }
            }

            // Validate tarball
            if (statMap == null || totalFiles == -1 || !dataTarballExtracted) {
                throw new Exception("Invalid tarball: missing metadata or data.tar.gz");
            }
        } finally {
            if (outerTarIn != null) {
                try {
                    outerTarIn.close();
                } catch (IOException e) {
                    Logger.w("Failed to close tar input stream");
                }
            }
            if (in instanceof CipherInputStream) {
                try {
                    in.close();
                } catch (IOException e) {
                    Logger.w("Failed to close cipher input stream");
                }
            }
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    Logger.w("Failed to close input stream");
                }
            }
        }

        // Erase files after metadata read, preserving data.tar.gz
        if (eraseBeforeRestore) {
            Set<String> preserveFiles = new HashSet<String>();
            preserveFiles.add(DATA_TARBALL);
            if (logFile != null) {
                preserveFiles.add(logFile.getName());
            }
            eraseFiles(context, preserveFiles);
        }

        // Extract inner data.tar.gz
        int processedFiles = 0;
        FileInputStream dataFis = null;
        GzipCompressorInputStream dataGzipIn = null;
        TarArchiveInputStream dataTarIn = null;
        try {
            dataFis = new FileInputStream(dataTarball);
            dataGzipIn = new GzipCompressorInputStream(dataFis);
            dataTarIn = new TarArchiveInputStream(dataGzipIn);
            TarArchiveEntry entry;
            while ((entry = dataTarIn.getNextTarEntry()) != null) {
                restoreEntry(context, dataTarIn, entry, statMap, restorePermissions, restoreTimestamps);
                if (!entry.isDirectory() && !entry.isSymbolicLink()) {
                    processedFiles++;
                    if (progressCallback != null && totalFiles > 0) {
                        progressCallback.onProgress((processedFiles * 100) / totalFiles);
                    }
                }
            }
        } finally {
            if (dataTarIn != null) {
                try {
                    dataTarIn.close();
                } catch (IOException e) {
                    Logger.w("Failed to close data tar input stream");
                }
            }
            if (dataGzipIn != null) {
                try {
                    dataGzipIn.close();
                } catch (IOException e) {
                    Logger.w("Failed to close gzip input stream");
                }
            }
            if (dataFis != null) {
                try {
                    dataFis.close();
                } catch (IOException e) {
                    Logger.w("Failed to close data file input stream");
                }
            }
            // Clean up data.tar.gz
            if (dataTarball.exists()) {
                if (dataTarball.delete()) {
                    Logger.d("Deleted temporary data.tar.gz: " + dataTarball.getAbsolutePath());
                } else {
                    Logger.w("Failed to delete temporary data.tar.gz: " + dataTarball.getAbsolutePath());
                }
            }
            // Clean up log file
            if (logFile != null && logFile.exists()) {
                Logger.close();
                if (logFile.delete()) {
                    Logger.d("Deleted log file: " + logFile.getAbsolutePath());
                } else {
                    Logger.w("Failed to delete log file: " + logFile.getAbsolutePath());
                }
                logFile = null;
            }
        }

        // Verify databases
        verifyDatabases(openDatabases);
    }

    /**
     * Read metadata from tarball.
     */
    private Map<String, Stat> readMetadata(TarArchiveInputStream tarIn) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        while ((bytesRead = tarIn.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
            Map<String, Stat> statMap = (Map<String, Stat>) ois.readObject();
            Logger.d("Loaded metadata from tarball, entries: " + statMap.size());
            return statMap;
        } catch (Exception e) {
            throw new Exception("Invalid metadata", e);
        } finally {
            if (ois != null) {
                try {
                    ois.close();
                } catch (IOException e) {
                    Logger.w("Failed to close object input stream");
                }
            }
        }
    }

    /**
     * Read total files metadata from tarball.
     */
    private int readTotalFilesMetadata(TarArchiveInputStream tarIn) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        while ((bytesRead = tarIn.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        try {
            String totalFilesStr = baos.toString().trim();
            int totalFiles = Integer.parseInt(totalFilesStr);
            Logger.d("Loaded total files metadata from tarball: " + totalFiles);
            return totalFiles;
        } catch (Exception e) {
            Logger.e("Failed to read total files metadata", e);
            throw new Exception("Invalid total files metadata", e);
        }
    }

    /**
     * Restore a single entry (file, directory, or symlink).
     */
    private void restoreEntry(Context context, TarArchiveInputStream tarIn, TarArchiveEntry entry,
                              Map<String, Stat> statMap, boolean restorePermissions, boolean restoreTimestamps) throws Exception {
        String entryName = entry.getName();
        String[] parts = entryName.split("/");
        if (parts.length >= MIN_TARBALL_PATH_PARTS && parts[0].equals(applicationId)) {
            String relativePath = entryName.substring(applicationId.length() + 1);
            File targetFile = new File(context.getApplicationInfo().dataDir, relativePath);

            if (entry.isDirectory()) {
                targetFile.mkdirs();
                if (restorePermissions) {
                    restorePermissions(targetFile, entry);
                } else {
                    setDefaultPermissions(targetFile, true);
                }
                if (restoreTimestamps) {
                    restoreTimestamps(targetFile, entry, statMap);
                }
                Logger.d("Restored directory: " + targetFile.getAbsolutePath());
            } else if (entry.isSymbolicLink()) {
                String linkTarget = entry.getLinkName();
                File parentDir = targetFile.getParentFile();
                if (parentDir != null) {
                    parentDir.mkdirs();
                }
                try {
                    NativeUtils.symlink(linkTarget, targetFile.getAbsolutePath());
                    Logger.d("Restored symlink: " + targetFile.getAbsolutePath() + " -> " + linkTarget);
                } catch (IOException e) {
                    Logger.w("Failed to restore symlink " + targetFile.getAbsolutePath() + ": " + e.getMessage());
                    throw new Exception("Failed to restore symlink: " + entryName, e);
                }
                if (restorePermissions) {
                    restorePermissions(targetFile, entry);
                }
                if (restoreTimestamps) {
                    restoreTimestamps(targetFile, entry, statMap);
                }
            } else {
                File parentDir = targetFile.getParentFile();
                if (parentDir != null) {
                    parentDir.mkdirs();
                }
                BufferedOutputStream bos = null;
                try {
                    bos = new BufferedOutputStream(new FileOutputStream(targetFile));
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = tarIn.read(buffer)) != -1) {
                        bos.write(buffer, 0, bytesRead);
                    }
                } finally {
                    if (bos != null) {
                        try {
                            bos.close();
                        } catch (IOException e) {
                            Logger.w("Failed to close output stream for " + targetFile.getAbsolutePath());
                        }
                    }
                }
                if (restorePermissions) {
                    restorePermissions(targetFile, entry);
                } else {
                    setDefaultPermissions(targetFile, false);
                }
                if (restoreTimestamps) {
                    restoreTimestamps(targetFile, entry, statMap);
                }
                Logger.d("Restored file: " + targetFile.getAbsolutePath());
            }
        }
    }

    /**
     * Restore permissions for a file or directory.
     */
    private void restorePermissions(File targetFile, TarArchiveEntry entry) {
        int mode = entry.getMode() & 0777;
        boolean permissionsSet = false;
        try {
            if (NativeUtils.isNativeLoaded()) {
                permissionsSet = NativeUtils.setFilePermissions(targetFile.getAbsolutePath(), mode);
            }
        } catch (IOException e) {
            Logger.w("Failed to set permissions via chmod for " + targetFile.getAbsolutePath() + ": " + e.getMessage());
        }
        if (permissionsSet) {
            Logger.d("Restored permissions via chmod: " + targetFile.getAbsolutePath() +
                    ", mode: " + Integer.toOctalString(mode));
        } else {
            Logger.w("Falling back to setReadable/setWritable for " + targetFile.getAbsolutePath());
            boolean ownerRead = (mode & 0400) != 0;
            boolean ownerWrite = (mode & 0200) != 0;
            boolean groupRead = (mode & 0040) != 0;
            boolean groupWrite = (mode & 0020) != 0;
            boolean othersRead = (mode & 0004) != 0;
            boolean othersWrite = (mode & 0002) != 0;

            targetFile.setReadable(false, false);
            targetFile.setWritable(false, false);

            targetFile.setReadable(ownerRead, true);
            targetFile.setWritable(ownerWrite, true);

            if (groupRead) {
                targetFile.setReadable(true, false);
            }
            if (groupWrite) {
                targetFile.setWritable(true, false);
            }

            if (othersRead || othersWrite) {
                Logger.w("Ignored others permissions (mode: " + Integer.toOctalString(mode) +
                        ") for " + targetFile.getAbsolutePath() + "; set to " +
                        (groupRead || groupWrite ? "0660" : "0600"));
            }

            Logger.d("Restored permissions via fallback: " + targetFile.getAbsolutePath() +
                    ", mode: " + (groupRead || groupWrite ? "0660" : "0600") +
                    ", original mode: " + Integer.toOctalString(mode));
        }
    }

    /**
     * Set default permissions (0600 for files, 0755 for directories).
     */
    private void setDefaultPermissions(File targetFile, boolean isDirectory) {
        targetFile.setReadable(true, true);
        targetFile.setWritable(true, true);
        targetFile.setReadable(isDirectory, false);
        targetFile.setWritable(isDirectory, false);
        Logger.d("Set default permissions (" + (isDirectory ? "0755" : "0600") + ") for " + targetFile.getAbsolutePath());
    }

    /**
     * Restore timestamps for a file or directory.
     */
    private void restoreTimestamps(File targetFile, TarArchiveEntry entry, Map<String, Stat> statMap) throws Exception {
        String entryName = entry.getName();
        Stat stat = statMap.get(entryName);
        boolean timesSet = false;
        if (stat != null && NativeUtils.isNativeLoaded()) {
            try {
                timesSet = NativeUtils.setFileTimes(
                        targetFile.getAbsolutePath(),
                        stat.st_atime, stat.st_atimeNsec,
                        stat.st_mtime, stat.st_mtimeNsec
                );
            } catch (IOException e) {
                Logger.w("Failed to set file times via utimensat for " + targetFile.getAbsolutePath() + ": " + e.getMessage());
            }
        }
        if (timesSet) {
            Logger.d("Restored file times via utimensat: " + targetFile.getAbsolutePath() +
                    ", atime: " + stat.st_atime + "." + stat.st_atimeNsec +
                    ", mtime: " + stat.st_mtime + "." + stat.st_mtimeNsec);
        } else {
            Logger.w("Falling back to setLastModified for " + targetFile.getAbsolutePath());
            long lastModified = entry.getLastModifiedDate().getTime();
            if (!targetFile.setLastModified(lastModified)) {
                Logger.w("Failed to set timestamp for " + targetFile.getName());
                throw new Exception("Failed to set timestamp for " + targetFile.getName());
            } else {
                Logger.d("Restored file mtime via fallback: " + targetFile.getAbsolutePath() +
                        ", mtime: " + lastModified);
            }
        }
    }

    /**
     * Close SQLite databases.
     */
    Map<String, SQLiteDatabase> closeDatabases(Context context) {
        Map<String, SQLiteDatabase> openDatabases = new HashMap<String, SQLiteDatabase>();
        File dataDir = new File(context.getApplicationInfo().dataDir);
        closeDatabasesRecursive(dataDir, openDatabases);
        return openDatabases;
    }

    private void closeDatabasesRecursive(File dir, Map<String, SQLiteDatabase> openDatabases) {
        if (!dir.exists() || !dir.isDirectory()) {
            return;
        }
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile() && isValidSQLiteDatabase(file)) {
                    try {
                        SQLiteDatabase db = SQLiteDatabase.openDatabase(
                                file.getAbsolutePath(),
                                null,
                                SQLiteDatabase.OPEN_READONLY
                        );
                        if (db.isOpen()) {
                            openDatabases.put(file.getAbsolutePath(), db);
                            Logger.d("Closed database: " + file.getAbsolutePath());
                        }
                    } catch (SQLiteException e) {
                        Logger.w("Failed to open/close database " + file.getAbsolutePath() + ": " + e.getMessage());
                    }
                } else if (file.isDirectory()) {
                    closeDatabasesRecursive(file, openDatabases);
                }
            }
        }
    }

    /**
     * Erase existing files.
     *
     * @param context       The calling context.
     * @param preserveFiles Files to preserve (e.g., data.tar.gz).
     */
    private void eraseFiles(Context context, Set<String> preserveFiles) {
        File dataDir = new File(context.getApplicationInfo().dataDir);
        eraseFilesRecursive(dataDir, preserveFiles);
    }

    private void eraseFilesRecursive(File dir, Set<String> preserveFiles) {
        if (!dir.exists() || !dir.isDirectory()) {
            return;
        }
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (preserveFiles != null && preserveFiles.contains(file.getName())) {
                    Logger.d("Preserving file: " + file.getAbsolutePath());
                    continue;
                }
                if (file.isFile()) {
                    if (file.delete()) {
                        Logger.d("Deleted file: " + file.getAbsolutePath());
                    } else {
                        Logger.w("Failed to delete file: " + file.getAbsolutePath());
                    }
                } else if (file.isDirectory()) {
                    eraseFilesRecursive(file, preserveFiles);
                    if (file.delete()) {
                        Logger.d("Deleted directory: " + file.getAbsolutePath());
                    } else {
                        Logger.w("Failed to delete directory: " + file.getAbsolutePath());
                    }
                }
            }
        }
    }

    /**
     * Verify database integrity.
     */
    private void verifyDatabases(Map<String, SQLiteDatabase> openDatabases) throws Exception {
        for (String dbPath : openDatabases.keySet()) {
            File dbFile = new File(dbPath);
            if (dbFile.exists()) {
                try {
                    SQLiteDatabase db = SQLiteDatabase.openDatabase(
                            dbFile.getAbsolutePath(),
                            null,
                            SQLiteDatabase.OPEN_READONLY
                    );
                    db.close();
                } catch (Exception e) {
                    throw new Exception("Failed to verify database: " + dbPath, e);
                }
            }
        }
        for (SQLiteDatabase db : openDatabases.values()) {
            if (db.isOpen()) {
                db.close();
            }
        }
    }

    // Encryption mode
    public enum EncryptionMode {
        NONE,  // No encryption
        WEAK,  // AES-128 with password as key
        STRONG // AES-128 with PBKDF2-derived key
    }

    /**
     * Callback for progress updates.
     */
    public interface ProgressCallback {
        void onProgress(int progress);
    }

    /**
     * Configuration for backup retention policy.
     */
    public static class BackupRetentionPolicy {
        private final int retentionDays;
        private final int maxBackups;

        /**
         * Constructor for retention policy.
         *
         * @param retentionDays Delete backups older than this number of days (0 to disable).
         * @param maxBackups    Keep at most this number of backups, deleting oldest (0 to disable).
         */
        public BackupRetentionPolicy(int retentionDays, int maxBackups) {
            this.retentionDays = Math.max(0, retentionDays);
            this.maxBackups = Math.max(0, maxBackups);
        }

        /**
         * Default policy: keep no existing backups (delete all before new backup).
         */
        public static BackupRetentionPolicy getDefault() {
            return new BackupRetentionPolicy(0, 1);
        }
    }
}
