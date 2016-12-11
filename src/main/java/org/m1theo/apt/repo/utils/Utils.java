/**
 * Copyright (c) 2010-2013, theo@m1theo.org.
 * 
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.m1theo.apt.repo.utils;

import org.apache.commons.codec.binary.Hex;
import org.m1theo.apt.repo.exceptions.AptRepoException;

import java.io.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Providing utilities as static methods.
 * 
 * @author Theo Weiss
 * @since 0.1.0
 * 
 */
public class Utils {

  /**
   * Compute the given message digest for a file.
   * 
   * @param hashType algorithm to be used (as {@code String})
   * @param file File to compute the digest for (as {@code File}).
   * @return A {@code String} for the hex encoded digest.
   * @throws AptRepoException
   */
  public static String getDigest(String hashType, File file) throws AptRepoException {
    try {
      FileInputStream fis = new FileInputStream(file);
      BufferedInputStream bis = new BufferedInputStream(fis);
      MessageDigest digest = MessageDigest.getInstance(hashType);
      DigestInputStream dis = new DigestInputStream(bis, digest);
      @SuppressWarnings("unused")
      int ch;
      while ((ch = dis.read()) != -1);
      String hex = new String(Hex.encodeHex(digest.digest()));
      fis.close();
      bis.close();
      dis.close();
      return hex;
    } catch (NoSuchAlgorithmException e) {
      throw new AptRepoException("could not create digest", e);
    } catch (FileNotFoundException e) {
      throw new AptRepoException("could not create digest", e);
    } catch (IOException e) {
      throw new AptRepoException("could not create digest", e);
    }
  }

  /**
   * Compute md5, sha1, sha256 message digest for a file.
   * 
   * @param file File to compute the digest for (as {@code File}).
   * @return {@link DefaultHashes} with the computed digests.
   * @throws AptRepoException
   */
  public static DefaultHashes getDefaultDigests(File file) throws AptRepoException {
    DefaultHashes h = new DefaultHashes();
      for (Hashes hash : Hashes.values()) {
        String hex = getDigest(hash.toString(), file);
        switch (Hashes.values()[hash.ordinal()]) {
          case MD5:
            h.setMd5(hex);
            break;
          case SHA1:
            h.setSha1(hex);
            break;
          case SHA256:
            h.setSha256(hex);
            break;
          case SHA512:
            h.setSha512(hex);
            break;
          default:
            throw new AptRepoException("unknown hash type: " + hash.toString());
        }
      }
      return h;
  }

}
