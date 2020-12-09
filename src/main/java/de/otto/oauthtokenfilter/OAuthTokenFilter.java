package de.otto.oauthtokenfilter;

import static jakarta.ws.rs.core.Response.Status.UNAUTHORIZED;

import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Authorizes a JAX-RS client against a service using OAuth2.
 */
public class OAuthTokenFilter implements ClientRequestFilter, ClientResponseFilter {

  private static final long EXPIRES_IMMEDIATELY = 0L;
  private Optional<Long> tokenLifetimeInSeconds;
  private LocalDateTime accessTokenExpires;
  private Client client;
  private String username;
  private String password;
  private String clientId;
  private String clientSecret;
  private String loginUrl;
  private String accessToken;
  private String refreshToken;
  private String grant_type;

  /**
   * Filters outgoing requests, adding an OAuth2-Token to the header.
   * @param requestContext The request context.
   */
  @Override
  public void filter(ClientRequestContext requestContext) {
    requestContext.getHeaders().add("Authorization", "Bearer " + getOAuth2Token());
  }

  /**
   * Filters the service's responses; if the service responds with a 401 UNAUTHORIZED,
   * e.g. because the session was manually reset, the access token is reset.
   * @param requestContext The request context; not used in this function.
   * @param responseContext The service's response context, including the response code.
   */
  @Override
  public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) {
    Response.StatusType statusInfo = responseContext.getStatusInfo();
    if (statusInfo.equals(UNAUTHORIZED)) {
      resetAccessToken();
    }
  }

  /**
   * A Builder function for the OAuthTokenFilter.
   * @return An instance of the static inner class OAuthTokenFilterBuilder.
   */
  public static OAuthTokenFilterBuilder builder() {
    return new OAuthTokenFilterBuilder();
  }

  private String getOAuth2Token() {
    if (isTokenValid()) {
      return accessToken;
    } else {
      Form form = new Form();
      if(refreshToken != null) {
        fillFormUsingRefreshToken(form);
      } else {
        fillFormUsingCredentials(form);
      }

      LocalDateTime timestamp = LocalDateTime.now().plusSeconds(tokenLifetimeInSeconds.orElse(
          EXPIRES_IMMEDIATELY));

      Response response = client.target(loginUrl)
          .request()
          .post(Entity.form(form));

      JsonObject json = response.readEntity(JsonObject.class);

      if(hasExpirationTime(json)) {
        timestamp = LocalDateTime.now().plusSeconds(
            json.getJsonNumber("expires_in").longValue());
      }

      accessToken = Optional.ofNullable(json.getString("access_token", null))
          .orElseThrow(() -> new AccessTokenNotAvailableException(
              "No access token provided in response:" + json));
      if(hasRefreshToken(json)) {
        refreshToken = json.getString("refresh_token");
      }
      accessTokenExpires = timestamp;
    }
    return accessToken;
  }

  private void fillFormUsingRefreshToken(Form form) {
    addParam(form, "grant_type", grant_type);
    addParam(form, "refresh_token", refreshToken);
  }

  void fillFormUsingCredentials(Form form) {
    addParam(form, "grant_type", grant_type);
    addParam(form, "username", username);
    addParam(form, "password", password);
    addParam(form, "client_id", clientId);
    addParam(form, "client_secret", clientSecret);
  }

  private void addParam(Form form, String key, String value) {
    if (value != null && !value.isEmpty()) {
      form.param(key, value);
    }
  }

  private boolean isTokenValid() {
    return accessToken != null && LocalDateTime.now().isBefore(accessTokenExpires);
  }

  private void resetAccessToken() {
    accessTokenExpires = LocalDateTime.now();
  }

  private boolean hasRefreshToken(JsonObject token) {
    return token.getString("refresh_token", null) != null;
  }

  private boolean hasExpirationTime(JsonObject token) {
    return token.getJsonNumber("expires_in") != null;
  }

  /**
   * A Builder class for the OAuthTokenFilter.
   * The tokenLifeTimeInSeconds field is not required if your OAuth2-Tokens come with the
   * "expires_in" field. If neither tokenLifeTimeInSeconds nor "expires_in" is provided,
   * your tokens will always expire after one usage.
   * You can also decide to pass your own client to the class; if you don't,
   * it will be generated for you in the build() function.
   */

  public static class OAuthTokenFilterBuilder {
    private OAuthTokenFilter filter = new OAuthTokenFilter();

    public OAuthTokenFilterBuilder username (String username) {
      filter.username = username;
      return this;
    }

    public OAuthTokenFilterBuilder password (String password) {
      filter.password = password;
      return this;
    }

    public OAuthTokenFilterBuilder clientId (String clientId) {
      filter.clientId = clientId;
      return this;
    }

    public OAuthTokenFilterBuilder clientSecret (String clientSecret) {
      filter.clientSecret = clientSecret;
      return this;
    }

    public OAuthTokenFilterBuilder loginUrl (String loginUrl) {
      filter.loginUrl = loginUrl;
      return this;
    }

    public OAuthTokenFilterBuilder tokenLifetimeInSeconds (Long tokenLifetimeInSeconds) {
      filter.tokenLifetimeInSeconds = Optional.ofNullable(tokenLifetimeInSeconds);
      return this;
    }

    public OAuthTokenFilterBuilder client (Client client) {
      filter.client = client;
      return this;
    }

    public OAuthTokenFilterBuilder grant_type (String grant_type) {
      filter.grant_type = grant_type;
      return this;
    }

    public OAuthTokenFilter build() {
      if (filter.grant_type == null) {
        filter.grant_type = "password";
      }
      return filter;
    }
  }

  public class AccessTokenNotAvailableException extends RuntimeException {
    public AccessTokenNotAvailableException(String message) {
      super(message);
    }
  }
}
