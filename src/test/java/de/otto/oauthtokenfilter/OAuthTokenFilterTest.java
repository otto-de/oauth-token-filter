package de.otto.oauthtokenfilter;

import static javax.json.Json.createObjectBuilder;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.assertj.core.api.Java6BDDAssertions.then;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;

import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.client.Client;
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

  private static final String DUMMY_TOKEN = "dummyToken";
  private static final JsonObject DUMMY_JSON = createObjectBuilder()
      .add("access_token", DUMMY_TOKEN).build();
  private static final String DUMMY_USERNAME = "dummyUsername";
  private static final String DUMMY_LOGIN_URL = "http://dummyLoginUrl";
  private static final String DUMMY_PASSWORD = "dummyPassword";
  private static final String DUMMY_CLIENT_ID = "dummyClientId";
  private static final String DUMMY_CLIENT_SECRET = "dummyClientSecret";
  private static final Long DUMMY_TOKEN_LIFETIME = 7200L;
  @Mock
  private Client client;
  @Mock
  private WebTarget target;
  @Mock
  private Builder builder;
  @Mock
  private Response response;
  @Captor
  private ArgumentCaptor<Entity> captor;
  @Mock
  private ClientResponseContext responseContext;

  private OAuthTokenFilter testee;

  private static Entry<String, List<String>> param(String name, String value) {
    return new java.util.AbstractMap.SimpleEntry<>(name, Arrays.asList(value));
  }

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
        .build();
  }

  @Test
  public void shouldGetOAuth2Token() {
    given(response.readEntity(any(Class.class))).willReturn(DUMMY_JSON);
    String token = testee.getOAuth2Token();

    then(token).isEqualTo(DUMMY_TOKEN);
    BDDMockito.then(builder).should().post(captor.capture());
    Form form = (Form) captor.getValue().getEntity();
    MultivaluedMap<String, String> params = form.asMap();
    then(params).containsExactly(
        param("grant_type", "password"),
        param("username", DUMMY_USERNAME),
        param("password", DUMMY_PASSWORD),
        param("client_id", DUMMY_CLIENT_ID),
        param("client_secret", DUMMY_CLIENT_SECRET));
  }

  @Test
  public void shouldThrowExceptionOnResponseWithoutAccessToken() {
    JsonObject jsonWithoutAccessToken = createObjectBuilder()
        .add("dummy", "dummy").build();
    given(response.readEntity(any(Class.class))).willReturn(jsonWithoutAccessToken);

    Throwable throwable = catchThrowable(() -> testee.getOAuth2Token());

    then(throwable).isInstanceOf(AccessTokenNotAvailableException.class);
  }

  @Test
  public void shouldThrowExceptionOnNoObjectResponse() {
    JsonObject emptyJsonObject = Json.createObjectBuilder().build();
    given(response.readEntity(any(Class.class))).willReturn(emptyJsonObject);

    Throwable throwable = catchThrowable(() -> testee.getOAuth2Token());

    then(throwable).isInstanceOf(AccessTokenNotAvailableException.class);
  }

  @Test
  public void shouldReturnSameToken() {
    given(response.readEntity(any(Class.class))).willReturn(DUMMY_JSON);
    String firstToken = testee.getOAuth2Token();

    String secondToken = testee.getOAuth2Token();

    then(secondToken).isEqualTo(firstToken);
  }

  @Test
  public void shouldTriggerForceRefreshToken() {
    JsonObject newToken = createObjectBuilder()
        .add("access_token", "newtoken").build();
    given(response.readEntity(any(Class.class))).willReturn(DUMMY_JSON, newToken);
    given(responseContext.getStatusInfo()).willReturn(UNAUTHORIZED);
    testee.getOAuth2Token();

    testee.filter(null, responseContext);

    then(testee.getOAuth2Token()).isEqualTo(newToken.getString("access_token"));
  }
}
