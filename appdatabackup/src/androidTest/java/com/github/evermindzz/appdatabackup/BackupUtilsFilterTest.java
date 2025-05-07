package com.github.evermindzz.appdatabackup;

import android.content.Context;

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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class BackupUtilsFilterTest {

    private Context context;
    private BackupUtils backupUtils;
    private File testDir;

    @Before
    public void setUp() throws IOException {
        context = ApplicationProvider.getApplicationContext();
        backupUtils = new BackupUtils(context, context.getCacheDir());

        // Create test directory structure under dataDir
        File dataDir = new File(context.getApplicationInfo().dataDir);
        testDir = new File(dataDir, "testdir");
        testDir.mkdirs();

        // Create subdir (will match filter)
        File subDir = new File(testDir, "subdir");
        subDir.mkdirs();
        File haveFile = new File(subDir, "haveFile.txt");
        File extraFile = new File(subDir, "extraFile.txt");
        haveFile.createNewFile();
        extraFile.createNewFile();

        // Create subSubDir under subdir (non-matching, should be included)
        File subSubDir = new File(subDir, "subSubDir");
        subSubDir.mkdirs();
        File subSubFile = new File(subSubDir, "subSubFile.txt");
        subSubFile.createNewFile();

        // Create otherDir with a matching file
        File otherDir = new File(testDir, "otherDir");
        otherDir.mkdirs();
        File otherFile = new File(otherDir, "otherFile.txt");
        otherFile.createNewFile();

        // Create unusedDir (non-matching, should be excluded)
        File unusedDir = new File(testDir, "unusedDir");
        unusedDir.mkdirs();
        File unusedFile = new File(unusedDir, "unusedFile.txt");
        unusedFile.createNewFile();
    }

    @After
    public void tearDown() {
        // Clean up test directory
        if (testDir != null && testDir.exists()) {
            deleteRecursive(testDir);
        }
    }

    @Test
    public void testCreateTarball_withFileFilter_includesMatchingDirsAndFiles() throws Exception {
        // Define regex filter for a directory and a file
        Pattern fileFilter = Pattern.compile("(testdir/subdir|testdir/otherDir/otherFile.txt)");

        // Create tarball
        File tarballFile = backupUtils.createTarball(
                context,
                null, // No password
                BackupUtils.EncryptionMode.NONE,
                fileFilter,
                null, // No progress callback
                BackupUtils.BackupRetentionPolicy.getDefault()
        );

        // Verify tarball exists
        assertTrue("Tarball should exist", tarballFile.exists());

        // Extract and verify inner data.tar.gz
        File dataTarball = extractDataTarball(tarballFile);
        List<String> tarballFiles = getTarballFilePaths(dataTarball);
        Collections.sort(tarballFiles); // Sort for consistent comparison

        // Expected files and directories
        List<String> expectedFiles = new ArrayList<>();
        String packageName = context.getPackageName();
        expectedFiles.add(packageName + "/"); // Root directory
        expectedFiles.add(packageName + "/testdir/"); // parent of Matching filters
        expectedFiles.add(packageName + "/testdir/subdir/"); // Matches filter
        expectedFiles.add(packageName + "/testdir/subdir/haveFile.txt"); // In matching directory
        expectedFiles.add(packageName + "/testdir/subdir/extraFile.txt"); // In matching directory
        expectedFiles.add(packageName + "/testdir/subdir/subSubDir/"); // In matching directory
        expectedFiles.add(packageName + "/testdir/subdir/subSubDir/subSubFile.txt"); // In matching directory
        expectedFiles.add(packageName + "/testdir/otherDir/"); // Parent of matching file
        expectedFiles.add(packageName + "/testdir/otherDir/otherFile.txt"); // Matches filter
        Collections.sort(expectedFiles); // Sort for consistent comparison

        for (String f : expectedFiles) {
            System.out.println("DBG expected: " + f);
        }

        for (String f : tarballFiles) {
            System.out.println("DBG actual  : " + f);
        }


        // Verify only expected files are included
        assertEquals("Tarball should contain exactly the expected files and directories",
                expectedFiles.size(), tarballFiles.size());
        for (String expectedFile : expectedFiles) {
            assertTrue("Tarball should contain " + expectedFile, tarballFiles.contains(expectedFile));
        }

        // Explicitly verify subSubDir is included
        String subSubDirPath = packageName + "/testdir/subdir/subSubDir/";
        assertTrue("Tarball should contain subSubDir: " + subSubDirPath, tarballFiles.contains(subSubDirPath));

        // Clean up
        if (dataTarball.exists()) {
            dataTarball.delete();
        }
        if (tarballFile.exists()) {
            tarballFile.delete();
        }
    }

    private File extractDataTarball(File tarballFile) throws IOException {
        File dataTarball = new File(context.getCacheDir(), "data.tar.gz");
        try (FileInputStream fis = new FileInputStream(tarballFile);
             TarArchiveInputStream tarIn = new TarArchiveInputStream(fis)) {
            TarArchiveEntry entry;
            while ((entry = tarIn.getNextTarEntry()) != null) {
                if (entry.getName().equals(context.getPackageName() + "/data.tar.gz")) {
                    try (FileOutputStream fos = new FileOutputStream(dataTarball)) {
                        byte[] buffer = new byte[8192];
                        int bytesRead;
                        while ((bytesRead = tarIn.read(buffer)) != -1) {
                            fos.write(buffer, 0, bytesRead);
                        }
                    }
                    break;
                }
            }
        }
        return dataTarball;
    }

    private List<String> getTarballFilePaths(File dataTarball) throws IOException {
        List<String> filePaths = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(dataTarball);
             GzipCompressorInputStream gzipIn = new GzipCompressorInputStream(fis);
             TarArchiveInputStream tarIn = new TarArchiveInputStream(gzipIn)) {
            TarArchiveEntry entry;
            while ((entry = tarIn.getNextTarEntry()) != null) {
                filePaths.add(entry.getName());
            }
        }
        return filePaths;
    }

    private void deleteRecursive(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }
}
