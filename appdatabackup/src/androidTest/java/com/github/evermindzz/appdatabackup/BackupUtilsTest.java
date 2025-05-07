package com.github.evermindzz.appdatabackup;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Instrumentation tests for BackupUtils.
 */
@RunWith(AndroidJUnit4.class)
public class BackupUtilsTest {
    private Context context;
    private BackupUtils backupUtils;
    private File dataDir;
    private File cacheDir;
    private File testDbFile;
    private File testFile;
    private File testSymlink;

    @Before
    public void setUp() throws Exception {
        // Get app context
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        backupUtils = new BackupUtils(context, context.getCacheDir());
        dataDir = new File(context.getApplicationInfo().dataDir);
        cacheDir = context.getCacheDir();

        // Clean directory
        cleanDirectory(dataDir);

        // recreate dirs
        dataDir = new File(context.getApplicationInfo().dataDir);
        dataDir.mkdir();
        cacheDir = context.getCacheDir();
        cacheDir.mkdir();

        // Create test data in /data/data/<package>/
        File testDir = new File(dataDir, "testdir/subdir");
        testDir.mkdirs();
        testFile = new File(dataDir, "testdir/testfile.txt");
        writeFile(testFile, "test content");
        testDbFile = new File(dataDir, "databases/test.db");
        testDbFile.getParentFile().mkdirs();
        createTestDatabase(testDbFile);
        testSymlink = new File(dataDir, "testdir/symlink");
        Runtime.getRuntime().exec("ln -s " + testFile.getAbsolutePath() + " " + testSymlink.getAbsolutePath()).waitFor();
    }

    @After
    public void tearDown() throws Exception {
        // Clean test data
        cleanDirectory(new File(dataDir, "testdir"));
        cleanDirectory(new File(dataDir, "databases"));
        cleanDirectory(cacheDir);
        // Ensure databases are closed
        backupUtils.closeDatabases(context);
    }

    @Test
    public void testCreateTarball_DefaultRetentionPolicy() throws Exception {
        // Setup: Create existing backups
        createTestBackupFile("2025-05-01_12-00-00");
        createTestBackupFile("2025-05-02_12-00-00");

        // Execute: Create tarball with default retention policy
        File tarball = backupUtils.createTarball(context, null, BackupUtils.EncryptionMode.NONE, null, null, null);

        // Verify: Only the new tarball exists
        File[] cacheFiles = cacheDir.listFiles();
        assertNotNull(cacheFiles);
        assertEquals(1, cacheFiles.length);
        assertEquals(tarball.getName(), cacheFiles[0].getName());

        // Verify tarball contents
        verifyTarballContents(tarball, context.getPackageName());
    }

    @Test
    public void testCreateTarball_CustomRetentionPolicy() throws Exception {
        // Setup: Create existing backups with different timestamps
        createTestBackupFile("2025-04-01_11-00-00"); // Older than 7 days
        createTestBackupFile("2025-04-01_12-00-00"); // Older than 7 days
        createTestBackupFile("2025-05-01_12-00-00"); // Within 7 days
        createTestBackupFile("2025-05-02_12-00-00"); // Within 7 days

        // Execute: Create tarball with custom retention policy (7 days, max 2 backups)
        BackupUtils.BackupRetentionPolicy policy = new BackupUtils.BackupRetentionPolicy(7, 1);
        File tarball = backupUtils.createTarball(context, null, BackupUtils.EncryptionMode.NONE, null, null, policy);

        // Verify: Only 2 backups remain (new tarball + 2025-05-02)
        File[] cacheFiles = cacheDir.listFiles();
        assertNotNull(cacheFiles);
        assertEquals(2, cacheFiles.length);
        boolean foundNew = false, foundMay2 = false;
        for (File file : cacheFiles) {
            if (file.getName().equals(tarball.getName())) foundNew = true;
            if (file.getName().contains("2025-05-02")) foundMay2 = true;
        }
        assertTrue(foundNew);
        assertTrue(foundMay2);
    }

    @Test
    public void testRestoreTarball() throws Exception {
        // Setup: Create a tarball
        File tarball = backupUtils.createTarball(context, null, BackupUtils.EncryptionMode.NONE, null, null, null);

        // Clear data directory except cache
        cleanDirectory(new File(dataDir, "testdir"));
        cleanDirectory(new File(dataDir, "databases"));
        assertFalse(testFile.exists());
        assertFalse(testDbFile.exists());

        // Execute: Restore tarball
        Uri tarballUri = Uri.fromFile(tarball);
        backupUtils.restoreTarball(
                InstrumentationRegistry.getInstrumentation().getTargetContext(),
                tarballUri,
                null,
                BackupUtils.EncryptionMode.NONE,
                true,
                true,
                true,
                null
        );

        // Verify: Files and database restored
        assertTrue(testFile.exists());
        assertEquals("test content", readFile(testFile));
        assertTrue(testDbFile.exists());
        assertTrue(backupUtils.isValidSQLiteDatabase(testDbFile));
        assertTrue(testSymlink.exists());
        assertTrue(testSymlink.isFile()); // Symlink points to testfile.txt
    }

    @Test
    public void testCreateTarball_WithEncryption() throws Exception {
        // Execute: Create tarball with STRONG encryption
        String password = "testpassword";
        File tarball = backupUtils.createTarball(context, password, BackupUtils.EncryptionMode.STRONG, null, null, null);

        // Verify: Tarball created
        assertTrue(tarball.exists());

        // Attempt restore with wrong password
        Uri tarballUri = Uri.fromFile(tarball);
        try {
            backupUtils.restoreTarball(
                    InstrumentationRegistry.getInstrumentation().getTargetContext(),
                    tarballUri,
                    "wrongpassword",
                    BackupUtils.EncryptionMode.STRONG,
                    true,
                    true,
                    true,
                    null
            );
            fail("Expected exception with wrong password");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Corrupted TAR archive"));
        }

        // Restore with correct password
        backupUtils.restoreTarball(
                InstrumentationRegistry.getInstrumentation().getTargetContext(),
                tarballUri,
                password,
                BackupUtils.EncryptionMode.STRONG,
                true,
                true,
                true,
                null
        );

        // Verify: Files restored
        assertTrue(testFile.exists());
        assertEquals("test content", readFile(testFile));
    }

    @Test
    public void testCountFiles() throws Exception {
        // Execute: Count files with no filter
        int fileCount = backupUtils.countFiles(context, null);

        // Verify: Counts test files (testfile.txt, test.db, fake.db if present)
        assertTrue(fileCount >= 2); // testfile.txt, test.db

        // Execute: Count with filter
        Pattern filter = Pattern.compile(".*testfile\\.txt$");
        fileCount = backupUtils.countFiles(context, filter);

        // Verify: Only testfile.txt
        assertEquals(1, fileCount);
    }

    @Test
    public void testInvalidTarball() throws Exception {
        // Setup: Create an invalid tarball
        File invalidTarball = new File(cacheDir, "invalid.tar");
        writeFile(invalidTarball, "not a tarball");

        // Execute: Attempt to restore
        Uri tarballUri = Uri.fromFile(invalidTarball);
        try {
            backupUtils.restoreTarball(
                    InstrumentationRegistry.getInstrumentation().getTargetContext(),
                    tarballUri,
                    null,
                    BackupUtils.EncryptionMode.NONE,
                    true,
                    true,
                    true,
                    null
            );
            fail("Expected exception for invalid tarball");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Invalid tarball"));
        }
    }

    private void createTestDatabase(File dbFile) throws Exception {
        SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(dbFile.getAbsolutePath(), null);
        db.execSQL("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)");
        db.execSQL("INSERT INTO test (name) VALUES ('test')");
        db.close();
    }

    private void writeFile(File file, String content) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }
    }

    private String readFile(File file) throws Exception {
        byte[] buffer = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(buffer);
        }
        return new String(buffer, StandardCharsets.UTF_8);
    }

    private void cleanDirectory(File dir) {
        if (dir.exists()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        cleanDirectory(file);
                    }
                    file.delete();
                }
            }
            dir.delete();
        }
    }

    private void createTestBackupFile(String timestamp) throws Exception {
        String packageName = context.getPackageName().replace(".", "_");
        File backupFile = new File(cacheDir, packageName + "_" + timestamp + "_backup.tar");
        writeFile(backupFile, "dummy backup");
        // Set last modified time to match timestamp
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US);
        backupFile.setLastModified(sdf.parse(timestamp).getTime());
    }

    private void verifyTarballContents(File tarball, String applicationId) throws Exception {
        try (FileInputStream fis = new FileInputStream(tarball);
             TarArchiveInputStream tarIn = new TarArchiveInputStream(fis)) {
            TarArchiveEntry entry;
            Map<String, Boolean> expectedEntries = new HashMap<>();
            expectedEntries.put(applicationId + "/.backupUtils-metadata.stat", false);
            expectedEntries.put(applicationId + "/.backupUtils-metadata.total_files", false);
            expectedEntries.put(applicationId + "/data.tar.gz", false);

            while ((entry = tarIn.getNextTarEntry()) != null) {
                String name = entry.getName();
                if (expectedEntries.containsKey(name)) {
                    expectedEntries.put(name, true);
                }
            }

            for (Map.Entry<String, Boolean> e : expectedEntries.entrySet()) {
                assertTrue("Missing entry: " + e.getKey(), e.getValue());
            }

            // Verify data.tar.gz contents
            fis.getChannel().position(0);
            TarArchiveInputStream tarIn2 = new TarArchiveInputStream(fis);
            while ((entry = tarIn2.getNextTarEntry()) != null) {
                if (entry.getName().equals(applicationId + "/data.tar.gz")) {
                    try (GzipCompressorInputStream gzipIn = new GzipCompressorInputStream(tarIn2);
                         TarArchiveInputStream dataTarIn = new TarArchiveInputStream(gzipIn)) {
                        Map<String, Boolean> dataEntries = new HashMap<>();
                        dataEntries.put(applicationId + "/testdir/testfile.txt", false);
                        dataEntries.put(applicationId + "/databases/test.db", false);
                        dataEntries.put(applicationId + "/testdir/symlink", false);

                        TarArchiveEntry dataEntry;
                        while ((dataEntry = dataTarIn.getNextTarEntry()) != null) {
                            String name = dataEntry.getName();
                            if (dataEntries.containsKey(name)) {
                                dataEntries.put(name, true);
                            }
                        }

                        for (Map.Entry<String, Boolean> e : dataEntries.entrySet()) {
                            assertTrue("Missing data entry: " + e.getKey(), e.getValue());
                        }
                    }
                    break;
                }
            }
        }
    }
}