/**
 * Copyright (c) 2010-2013, theo@m1theo.org.
 * <p>
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.m1theo.apt.repo.builder;

import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.ar.ArArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.utils.IOUtils;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.m1theo.apt.repo.exceptions.AptRepoException;
import org.m1theo.apt.repo.packages.PackageEntry;
import org.m1theo.apt.repo.packages.Packages;
import org.m1theo.apt.repo.release.Release;
import org.m1theo.apt.repo.release.ReleaseInfo;
import org.m1theo.apt.repo.signing.PGPSigner;
import org.m1theo.apt.repo.utils.ControlHandler;
import org.m1theo.apt.repo.utils.DefaultHashes;
import org.m1theo.apt.repo.utils.Utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * @author theo@m1theo.org
 */
public class RepoBuilder {
  private static final String CONTROL_FILE_NAME = "./control";
  private static final String PACKAGES = "Packages";
  private static final String PACKAGES_GZ = "Packages.gz";
  private static final String RELEASE = "Release";
  private static final String RELEASEGPG = "Release.gpg";
  private static final String INRELEASE = "InRelease";
  private static final String DEFAULT_DIGEST = "SHA256";

  private List<File> debFiles = new ArrayList<>();
  private final File repoDir;
  private final boolean sign;
  private final File passphraseFile;
  private final File keyring;
  private final String keyId;
  private String passphrase;
  private final String digest;

  private File packagesFile;
  private File packagesGzFile;
  private Release release;

  public RepoBuilder(String repoDir) throws AptRepoException {
    this(repoDir, false, null, null, null, null, null);
  }

  public RepoBuilder(String repoDir, String keyring, String keyId, String
      passphrase) throws AptRepoException {
    this(repoDir, true, keyring, keyId, passphrase, null, DEFAULT_DIGEST);
  }

  public RepoBuilder(String repoDir, String keyring, String keyId, File passphraseFile)
      throws
      AptRepoException {
    this(repoDir, true, keyring, keyId, null, passphraseFile, DEFAULT_DIGEST);
  }

  private RepoBuilder(String repoDir, boolean sign, String keyring, String keyId, String
      passphrase, File passphraseFile, String digest) throws AptRepoException {
    Path repoPath = Paths.get(repoDir);
    if (!Files.exists(repoPath)) {
      if (Files.isDirectory(repoPath.getParent())) {
        try {
          Files.createDirectory(repoPath);
        } catch (IOException e) {
          throw new AptRepoException("creating repo directory failed: " + repoDir, e);
        }
      } else {
        throw new AptRepoException("repDir does not exist: " + repoDir);
      }
    }
    if (sign) {
      if (!Files.isRegularFile(Paths.get(keyring))) {
        throw new AptRepoException("keyring does not exist: " + keyring);
      }
      this.passphraseFile = passphraseFile;
      this.keyring = new File(keyring);
      this.keyId = keyId;
      this.passphrase = passphrase;
      this.digest = digest;
    } else {
      this.passphraseFile = null;
      this.keyring = null;
      this.keyId = null;
      this.passphrase = null;
      this.digest = null;
    }
    this.repoDir = new File(repoDir);
    this.sign = sign;
  }

  public void create() throws AptRepoException {
    createPackagesFile();
    createReleaseFile();
    if (sign) {
      sign();
    }
  }

  public void add(String debFile) throws AptRepoException {
    if (!Files.isRegularFile(Paths.get(debFile))) {
      throw new AptRepoException("file not found: " + debFile);
    }
    debFiles.add(new File(debFile));
  }

  private void createPackagesFile() throws AptRepoException {
    //TODO implement copy file?
    Packages packages = new Packages();
    for (File file : debFiles) {
      PackageEntry packageEntry = new PackageEntry();
      packageEntry.setSize(file.length());
      packageEntry.setSha1(Utils.getDigest("SHA-1", file));
      packageEntry.setSha256(Utils.getDigest("SHA-256", file));
      packageEntry.setSha512(Utils.getDigest("SHA-512", file));
      packageEntry.setMd5sum(Utils.getDigest("MD5", file));
      String fileName = file.getName();
      packageEntry.setFilename(fileName);
      //getLog().info("found deb: " + fileName);
      try {
        ArchiveInputStream control_tgz;
        ArArchiveEntry entry;
        TarArchiveEntry control_entry;
        ArchiveInputStream debStream =
            new ArchiveStreamFactory().createArchiveInputStream("ar", new FileInputStream(file));
        while ((entry = (ArArchiveEntry) debStream.getNextEntry()) != null) {
          if (entry.getName().equals("control.tar.gz")) {
            ControlHandler controlHandler = new ControlHandler();
            GZIPInputStream gzipInputStream = new GZIPInputStream(debStream);
            control_tgz =
                new ArchiveStreamFactory().createArchiveInputStream("tar", gzipInputStream);
            while ((control_entry = (TarArchiveEntry) control_tgz.getNextEntry()) != null) {
              //getLog().debug("control entry: " + control_entry.getName());
              if (control_entry.getName().equals(CONTROL_FILE_NAME)) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                IOUtils.copy(control_tgz, outputStream);
                String content_string = outputStream.toString("UTF-8");
                outputStream.close();
                controlHandler.setControlContent(content_string);
                //getLog().debug("control cont: " + outputStream.toString("utf-8"));
                break;
              }
            }
            control_tgz.close();
            if (controlHandler.hasControlContent()) {
              controlHandler.handle(packageEntry);
            } else {
              throw new AptRepoException("no control content found for: " + file.getName());
            }
            break;
          }
        }
        debStream.close();
        packages.addPackageEntry(packageEntry);

      } catch (UnsupportedEncodingException e) {
        throw new AptRepoException("Packages encoding exception", e);
      } catch (ArchiveException e) {
        throw new AptRepoException("Packages archive exception", e);
      } catch (IOException e) {
        throw new AptRepoException("Packages IOExeption", e);
      }
    }
    try {
      File packagesFile = new File(repoDir, PACKAGES);
      BufferedWriter packagesWriter = null;
      packagesWriter = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(
          packagesFile)));
      packagesWriter.write(packages.toString());
      packagesWriter.close();
      this.packagesFile = packagesFile;

      File packagesGzFile = new File(repoDir, PACKAGES_GZ);
      BufferedWriter packagesGzWriter = new BufferedWriter(new OutputStreamWriter(new GZIPOutputStream(new FileOutputStream(
          packagesGzFile))));
      packagesGzWriter.write(packages.toString());
      packagesGzWriter.close();
      this.packagesGzFile = packagesGzFile;
    } catch (FileNotFoundException e) {
      throw new AptRepoException("invalid repodir: " + repoDir, e);
    } catch (IOException e) {
      throw new AptRepoException("writing packages failed", e);
    }
  }

  private void createReleaseFile() throws AptRepoException {
    release = new Release();
    //
    // add Packages file
    //
    DefaultHashes hashes = Utils.getDefaultDigests(packagesFile);
    ReleaseInfo pinfo = new ReleaseInfo(PACKAGES, packagesFile.length(), hashes);
    release.addInfo(pinfo);

    //
    // add Packages.gz file
    DefaultHashes gzHashes = Utils.getDefaultDigests(packagesGzFile);
    ReleaseInfo gzPinfo = new ReleaseInfo(PACKAGES_GZ, packagesGzFile.length(), gzHashes);
    release.addInfo(gzPinfo);

    final File releaseFile = new File(repoDir, RELEASE);
    try {
      BufferedWriter releaseWriter = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(releaseFile)));
      releaseWriter.write(release.toString());
      releaseWriter.close();
    } catch (IOException e) {
      throw new AptRepoException("Release file got IOException", e);
    }
  }

  private void sign() throws AptRepoException {
    //getLog().debug("passphrase file will be used " + passphraseFile.getAbsolutePath());
    try {
      if (passphraseFile != null) {
        BufferedReader pwReader = new BufferedReader(new FileReader(passphraseFile));
        passphrase = pwReader.readLine();
        pwReader.close();
      }
      final File inReleaseFile = new File(repoDir, INRELEASE);
      final File releaseGpgFile = new File(repoDir, RELEASEGPG);
      PGPSigner signer = new PGPSigner(new FileInputStream(keyring), keyId, passphrase, getDigestCode(digest));
      signer.clearSignDetached(release.toString(), new FileOutputStream(releaseGpgFile));
      signer.clearSign(release.toString(), new FileOutputStream(inReleaseFile));
    } catch (FileNotFoundException e) {
      throw new AptRepoException("file not found", e);
    } catch (AptRepoException e) {
      throw new AptRepoException("aptRepoException", e);
    } catch (IOException e) {
      throw new AptRepoException("IOException", e);
    } catch (PGPException e) {
      throw new AptRepoException("PGPException", e);
    } catch (GeneralSecurityException e) {
      throw new AptRepoException("GeneralSecurityException", e);
    }
  }

  private static int getDigestCode(String digestName) throws AptRepoException {
    if ("SHA1".equals(digestName)) {
      return HashAlgorithmTags.SHA1;
    } else if ("MD2".equals(digestName)) {
      return HashAlgorithmTags.MD2;
    } else if ("MD5".equals(digestName)) {
      return HashAlgorithmTags.MD5;
    } else if ("RIPEMD160".equals(digestName)) {
      return HashAlgorithmTags.RIPEMD160;
    } else if ("SHA256".equals(digestName)) {
      return HashAlgorithmTags.SHA256;
    } else if ("SHA384".equals(digestName)) {
      return HashAlgorithmTags.SHA384;
    } else if ("SHA512".equals(digestName)) {
      return HashAlgorithmTags.SHA512;
    } else if ("SHA224".equals(digestName)) {
      return HashAlgorithmTags.SHA224;
    } else {
      throw new AptRepoException("unknown hash algorithm tag in digestName: " + digestName);
    }
  }
}
