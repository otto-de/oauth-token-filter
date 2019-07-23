package de.otto.oauthtokenfilter;

import static javax.json.Json.createObjectBuilder;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.assertj.core.api.Java6BDDAssertions.then;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;

import de.otto.oauthtokenfilter.OAuthTokenFilter.AccessTokenNotAvailableException;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class OAuthTokenFilterTest {

  private static final String DUMMY_ACCESS_TOKEN = "dummyToken";
  private static final JsonObject DUMMY_JSON = createObjectBuilder()
      .add("access_token", DUMMY_ACCESS_TOKEN)
      .build();
  private static final String DUMMY_REFRESH_TOKEN = "dummyRefreshToken";
  private static final String DUMMY_USERNAME = "dummyUsername";
  private static final String DUMMY_LOGIN_URL = "http://dummyLoginUrl";
  private static final String DUMMY_PASSWORD = "dummyPassword";
  private static final String DUMMY_CLIENT_ID = "dummyClientId";
  private static final String DUMMY_CLIENT_SECRET = "dummyClientSecret";
  private static final Long DUMMY_TOKEN_LIFETIME = 7200L;
  private static final int NUMBER_OF_CREDENTIALS = 5;
  private static final String DUMMY_GRANT_TYPE = "dummyGrantType";

  @Mock
  private Client client;
  @Mock
  private WebTarget target;
  @Mock
  private Builder builder;
  @Mock
  private Response response;
  @Mock
  private ClientResponseContext responseContext;
  @Mock
  private ClientRequestContext requestContext;
  @Mock
  private MultivaluedMap<String, Object> headers;
  @Captor
  private ArgumentCaptor<String> authHeader;

  @Captor
  private ArgumentCaptor<Entity<Form>> formCaptor;

  private OAuthTokenFilter testee;

  @Before
  public void setup() {
    given(client.target(anyString())).willReturn(target);
    given(target.request()).willReturn(builder);
    given(builder.post(any())).willReturn(response);
    testee = OAuthTokenFilter.builder()
        .client(client)
        .username(DUMMY_USERNAME)
        .password(DUMMY_PASSWORD)
        .clientId(DUMMY_CLIENT_ID)
        .clientSecret(DUMMY_CLIENT_SECRET)
        .loginUrl(DUMMY_LOGIN_URL)
        .tokenLifetimeInSeconds(DUMMY_TOKEN_LIFETIME)
        .grant_type(DUMMY_GRANT_TYPE)
        .build();
  }

  @Test
  public void shouldAddOAuth2TokenToRequest() {
    given(response.readEntity(JsonObject.class)).willReturn(DUMMY_JSON);
    given(requestContext.getHeaders()).willReturn(headers);

    testee.filter(requestContext);

    BDDMockito.then(headers).should().add(eq("Authorization"), authHeader.capture());
    then(authHeader.getValue()).isEqualTo("Bearer " + DUMMY_ACCESS_TOKEN);
  }

  @Test
  public void shouldThrowExceptionOnResponseWithoutAccessToken() {
    JsonObject jsonWithoutAccessToken = createObjectBuilder()
        .add("dummy", "dummy").build();
    given(response.readEntity(JsonObject.class)).willReturn(jsonWithoutAccessToken);

    Throwable throwable = catchThrowable(() -> testee.filter(requestContext));

    then(throwable).isInstanceOf(AccessTokenNotAvailableException.class);
  }

  @Test
  public void shouldThrowExceptionOnNoObjectResponse() {
    JsonObject emptyJsonObject = Json.createObjectBuilder().build();
    given(response.readEntity(JsonObject.class)).willReturn(emptyJsonObject);

    Throwable throwable = catchThrowable(() -> testee.filter(requestContext));

    then(throwable).isInstanceOf(AccessTokenNotAvailableException.class);
  }

  @Test
  public void shouldUseStoredToken() {
    given(response.readEntity(JsonObject.class)).willReturn(DUMMY_JSON,
        Json.createObjectBuilder().build());
    given(requestContext.getHeaders()).willReturn(headers);
    testee.filter(requestContext);

    testee.filter(requestContext);

    BDDMockito.then(headers).should(times(2)).add(
        eq("Authorization"), authHeader.capture());
    then(authHeader.getAllValues()).allMatch(i -> ("Bearer " + DUMMY_ACCESS_TOKEN).equals(i));
  }

  @Test
  public void shouldInvalidateTokenByReturningUnauthorized() {
    JsonObject newToken = createObjectBuilder()
        .add("access_token", "newtoken").build();
    given(response.readEntity(JsonObject.class)).willReturn(DUMMY_JSON, newToken);
    given(requestContext.getHeaders()).willReturn(headers);
    given(responseContext.getStatusInfo()).willReturn(UNAUTHORIZED);
    testee.filter(requestContext);

    invalidateToken();
    testee.filter(requestContext); //Gets a fresh token

    BDDMockito.then(headers).should(times(2)).add(
        eq("Authorization"), authHeader.capture());
    then(authHeader.getValue()).isEqualTo("Bearer newtoken");
  }

  private void invalidateToken() {
    testee.filter(null, responseContext);
  }

  @Test
  public void shouldCreateTokenThatExpiresImmediately() {
    JsonObject oauth2TokenWithZeroTokenLifetime = createObjectBuilder()
        .add("expires_in", 0)
        .add("access_token", "newtoken")
        .build();
    given(response.readEntity(JsonObject.class)).willReturn(oauth2TokenWithZeroTokenLifetime, DUMMY_JSON);
    given(requestContext.getHeaders()).willReturn(headers);
    testee.filter(requestContext);

    testee.filter(requestContext);

    BDDMockito.then(headers).should(times(2)).add(
        eq("Authorization"), authHeader.capture());
    then(authHeader.getAllValues().get(0)).isNotEqualTo(authHeader.getAllValues().get(1));
  }

  @Test
  public void shouldCreateTokenThatExpiresWithinFiveSeconds() {
    JsonObject oauth2TokenWithFiveSecondLifetime = createObjectBuilder()
        .add("expires_in", 5)
        .add("access_token", "newtoken")
        .build();
    given(response.readEntity(JsonObject.class)).willReturn(oauth2TokenWithFiveSecondLifetime);
    given(requestContext.getHeaders()).willReturn(headers);
    testee.filter(requestContext);

    testee.filter(requestContext);

    BDDMockito.then(headers).should(times(2)).add(
        eq("Authorization"), authHeader.capture());
    then(authHeader.getAllValues()).allMatch(token -> "Bearer newtoken".equals(token));
  }

  @Test
  public void shouldAuthenticateUsingRefreshToken() {
    JsonObject oauth2TokenWithRefreshToken = createObjectBuilder()
        .add("refresh_token", "dummyRefreshToken")
        .add("expires_in", 0)
        .add("access_token", DUMMY_REFRESH_TOKEN)
        .build();
    given(response.readEntity(JsonObject.class)).willReturn(oauth2TokenWithRefreshToken);
    given(requestContext.getHeaders()).willReturn(headers);
    testee.filter(requestContext);

    testee.filter(requestContext);

    BDDMockito.then(builder).should(times(2)).post(formCaptor.capture());
    then(formCaptor.getValue().getEntity().asMap().getFirst("refresh_token")).isEqualTo(DUMMY_REFRESH_TOKEN);
  }

  @Test
  public void shouldAuthenticateUsingCredentials() {
    given(requestContext.getHeaders()).willReturn(headers);
    given(response.readEntity(JsonObject.class)).willReturn(DUMMY_JSON);

    testee.filter(requestContext);

    BDDMockito.then(builder).should().post(formCaptor.capture());
    then(formCaptor.getValue().getEntity().asMap().getFirst("username")).isEqualTo(DUMMY_USERNAME);
    then(formCaptor.getValue().getEntity().asMap().getFirst("password")).isEqualTo(DUMMY_PASSWORD);
    then(formCaptor.getValue().getEntity().asMap().keySet().size()).isEqualTo(NUMBER_OF_CREDENTIALS);
  }
}
