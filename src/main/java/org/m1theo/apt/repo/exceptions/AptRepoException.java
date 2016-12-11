package org.m1theo.apt.repo.exceptions;

/**
 * @author theo@m1theo.org
 */
public class AptRepoException extends Exception{
  public AptRepoException(String message, Throwable cause) {
    super(message, cause);
  }

  public AptRepoException(String message) {
    super(message);
  }
}
