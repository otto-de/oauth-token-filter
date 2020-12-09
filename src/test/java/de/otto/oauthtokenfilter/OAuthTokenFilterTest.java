package de.otto.oauthtokenfilter;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static jakarta.json.Json.createObjectBuilder;
import static org.assertj.core.api.BDDAssertions.then;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import de.otto.oauthtokenfilter.OAuthTokenFilter.AccessTokenNotAvailableException;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OAuthTokenFilterTest {

  private static final String DUMMY_ACCESS_TOKEN = "dummyToken";
  private static final JsonObject DUMMY_JSON = createObjectBuilder()
      .add("access_token", DUMMY_ACCESS_TOKEN)
      .build();
  private static final String DUMMY_REFRESH_TOKEN = "dummyRefreshToken";
  private static final String DUMMY_USERNAME = "dummyUsername";
  private static final String DUMMY_PASSWORD = "dummyPassword";
  private static final String DUMMY_CLIENT_ID = "dummyClientId";
  private static final String DUMMY_CLIENT_SECRET = "dummyClientSecret";
  private static final Long DUMMY_TOKEN_LIFETIME = 7200L;
  private static final String DUMMY_GRANT_TYPE = "dummyGrantType";

  private final Client client = ClientBuilder.newClient();

  @Mock
  private ClientRequestContext requestContext;

  @Mock
  private MultivaluedMap<String, Object> headers;

  @Captor
  private ArgumentCaptor<String> authHeader;

  private OAuthTokenFilter testee;

  protected static WireMockServer wireMockServer;

  @BeforeAll
  static void startWireMockServer() {
    wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
    wireMockServer.start();
    WireMock.configureFor(wireMockServer.port());
  }

  @BeforeEach
  public final void resetWireMockServer() {
    wireMockServer.resetAll();
  }

  @AfterAll
  static void stopWireMockServer() {
    wireMockServer.stop();
  }

  @BeforeEach
  public void setup() {
    testee = OAuthTokenFilter.builder()
        .client(client)
        .username(DUMMY_USERNAME)
        .password(DUMMY_PASSWORD)
        .clientId(DUMMY_CLIENT_ID)
        .clientSecret(DUMMY_CLIENT_SECRET)
        .loginUrl(wireMockServer.url("/token"))
        .tokenLifetimeInSeconds(DUMMY_TOKEN_LIFETIME)
        .grant_type(DUMMY_GRANT_TYPE)
        .build();
  }

  @Test
  void shouldAddOAuth2TokenToRequest() {
    given(requestContext.getHeaders()).willReturn(headers);
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(DUMMY_JSON.toString())));

    testee.filter(requestContext);

    BDDMockito.then(headers).should().add(eq("Authorization"), authHeader.capture());
    then(authHeader.getValue()).isEqualTo("Bearer " + DUMMY_ACCESS_TOKEN);
  }

  @Test
  void shouldThrowExceptionOnResponseWithoutAccessToken() {
    JsonObject jsonWithoutAccessToken = createObjectBuilder()
        .add("dummy", "dummy").build();
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(jsonWithoutAccessToken.toString())));

    Throwable throwable = catchThrowable(() -> testee.filter(requestContext));

    then(throwable).isInstanceOf(AccessTokenNotAvailableException.class);
  }

  @Test
  void shouldThrowExceptionOnNoObjectResponse() {
    JsonObject emptyJsonObject = Json.createObjectBuilder().build();
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(emptyJsonObject.toString())));

    Throwable throwable = catchThrowable(() -> testee.filter(requestContext));

    then(throwable).isInstanceOf(AccessTokenNotAvailableException.class);
  }

  @Test
  void shouldUseStoredToken() {
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(DUMMY_JSON.toString())));
    given(requestContext.getHeaders()).willReturn(headers);

    testee.filter(requestContext);
    testee.filter(requestContext);

    wireMockServer.verify(1, postRequestedFor(urlPathEqualTo("/token")));
    BDDMockito.then(headers).should(times(2)).add(
        eq("Authorization"), authHeader.capture());
    then(authHeader.getAllValues()).allMatch(("Bearer " + DUMMY_ACCESS_TOKEN)::equals);
  }


  @Test
  void shouldCreateTokenThatExpiresImmediately() {
    JsonObject oauth2TokenWithZeroTokenLifetime = createObjectBuilder()
        .add("expires_in", 0)
        .add("access_token", "newtoken")
        .build();
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(oauth2TokenWithZeroTokenLifetime.toString())));
    given(requestContext.getHeaders()).willReturn(headers);

    testee.filter(requestContext);
    testee.filter(requestContext);

    wireMockServer.verify(2, postRequestedFor(urlPathEqualTo("/token")));
    BDDMockito.then(headers).should(times(2)).add(
        eq("Authorization"), authHeader.capture());
    then(authHeader.getAllValues()).allMatch(("Bearer newtoken")::equals);
  }

  @Test
  void shouldAuthenticateUsingRefreshToken() {
    JsonObject oauth2TokenWithRefreshToken = createObjectBuilder()
        .add("refresh_token", "dummyRefreshToken")
        .add("expires_in", 0)
        .add("access_token", DUMMY_REFRESH_TOKEN)
        .build();
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(oauth2TokenWithRefreshToken.toString())));
    given(requestContext.getHeaders()).willReturn(headers);

    testee.filter(requestContext);
    testee.filter(requestContext);

    List<LoggedRequest> tokenRequests =
        wireMockServer.findAll(postRequestedFor(urlPathEqualTo("/token")));
    then(tokenRequests.get(1).getBodyAsString()).contains("refresh_token");
  }

  @Test
  void shouldAuthenticateUsingCredentials() {
    given(requestContext.getHeaders()).willReturn(headers);
    wireMockServer.stubFor(WireMock.post(WireMock.urlPathEqualTo("/token"))
        .willReturn(WireMock.aResponse()
            .withHeader("Content-Type", "application/json")
            .withBody(DUMMY_JSON.toString())));

    testee.filter(requestContext);

    wireMockServer.verify(postRequestedFor(urlPathEqualTo("/token"))
        .withRequestBody(equalTo(
            "grant_type=dummyGrantType&username=dummyUsername&password=dummyPassword&client_id=dummyClientId&client_secret=dummyClientSecret")));
  }

  @Test
  void shouldReturnAFormWithoutUsernameAndPassword() {
    testee = OAuthTokenFilter.builder()
        .clientSecret(DUMMY_CLIENT_SECRET)
        .clientId(DUMMY_CLIENT_ID)
        .build();
    Form form = new Form();

    testee.fillFormUsingCredentials(form);
    then(form.asMap().get("username")).isEqualTo(null);
    then(form.asMap().get("password")).isEqualTo(null);
  }
}
