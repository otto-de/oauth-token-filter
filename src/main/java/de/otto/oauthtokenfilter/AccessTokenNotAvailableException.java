package de.otto.oauthtokenfilter;

public class AccessTokenNotAvailableException extends RuntimeException {

  public AccessTokenNotAvailableException(String message) {
    super(message);
  }
}
