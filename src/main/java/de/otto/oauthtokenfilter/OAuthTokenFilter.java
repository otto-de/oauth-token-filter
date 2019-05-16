package de.otto.oauthtokenfilter;

import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

import java.time.LocalDateTime;
import java.util.Optional;
import javax.json.JsonObject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.Response;
import lombok.Builder;

@Builder
public class OAuthTokenFilter implements ClientRequestFilter, ClientResponseFilter {

  private Long tokenLifetime;
  private LocalDateTime accessTokenExpires;
  private Client client;
  private String username;
  private String password;
  private String clientId;
  private String clientSecret;
  private String loginUrl;
  private String accessToken;

  @Override
  public void filter(ClientRequestContext requestContext) {
    requestContext.getHeaders().add("Authorization", "Bearer " + getOAuth2Token());
  }

  @Override
  public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) {
    Response.StatusType statusInfo = responseContext.getStatusInfo();
    if (statusInfo.equals(UNAUTHORIZED)) {
      forceRefreshToken();
    }
  }

  public String getOAuth2Token() {
    if (isTokenValid()) {
      return accessToken;
    } else {
      Form form = new Form();
      form.param("grant_type", "password");
      form.param("username", username);
      form.param("password", password);
      form.param("client_id", clientId);
      form.param("client_secret", clientSecret);

      LocalDateTime timestamp = LocalDateTime.now().plusSeconds(tokenLifetime);

      Response response = client.target(loginUrl)
          .request()
          .post(Entity.form(form));

      JsonObject json = response.readEntity(JsonObject.class);
      accessToken = Optional.ofNullable(json.getString("access_token", null))
          .orElseThrow(() -> new AccessTokenNotAvailableException(
              "No access token provided in response:" + json));
      accessTokenExpires = timestamp;
    }
    return accessToken;
  }

  private boolean isTokenValid() {
    return accessToken != null && LocalDateTime.now().isBefore(accessTokenExpires);
  }

  private void forceRefreshToken() {
    accessTokenExpires = LocalDateTime.now();
  }
}
