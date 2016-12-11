package org.m1theo.apt.repo.builder;

import org.junit.Test;

/**
 * @author theo@m1theo.org
 */
public class RepoBuilderTest {

  @Test
  public void createEmpty() throws Exception {
    String repoDir = "build/apt-repo-test-empty";
    RepoBuilder builder = new RepoBuilder(repoDir);
    builder.create();
  }

  @Test
  public void create() throws Exception {
    String repoDir = "build/apt-repo-test-1";
    String deb1 = "src/test/resources/fake_1.0_arm64.deb";
    RepoBuilder builder = new RepoBuilder(repoDir);
    builder.add(deb1);
    builder.create();
  }

  @Test
  public void create2() throws Exception {
    String repoDir = "build/apt-repo-test-2";
    String deb1 = "src/test/resources/fake_1.0_arm64.deb";
    String deb2 = "src/test/resources/fake_1.0_mips.deb";
    RepoBuilder builder = new RepoBuilder(repoDir);
    builder.add(deb1);
    builder.add(deb2);
    builder.create();
  }

  @Test
  public void createSigning() throws Exception {
    String id = "88C86652";
    String digest = "SHA512";
    String keyringPath = "src/test/resources/<add a keyring file here>";
    String repoDir = "build/apt-repo-test-2";
    String deb1 = "src/test/resources/fake_1.0_arm64.deb";
    new RepoBuilder(repoDir, true, null, keyring, id, "hans", digest);
    RepoBuilder builder = new RepoBuilder(repoDir);
    builder.add(deb1);
    builder.create();
  }
}