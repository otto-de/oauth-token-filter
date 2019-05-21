# OAuthTokenFilter

The OAuthTokenFilter is an implementation of JEEs ClientRequestFilter and ClientResponseFilter. 
If you're using JEE to work with a service that uses OAuth2 for authorization,
you can use the OAuthTokenFilter to automatically authorize you.
It filters your requests to that service, adds OAuth2-Tokens to your requests, caches them, 
checks them for validity and refreshes them when necessary.

## Installing / Getting started

To include the OAuthTokenFilter in your project, simply add it as a Maven Dependency. 

```shell
  <dependency>
    <groupId>de.otto.oauthtokenfilter</groupId>
    <artifactId>oauth-token-filter</artifactId>
    <version>1.0</version>
  </dependency>
  ```

### Initial Configuration

Upon using your ClientBuilder, call 
```shell
import de.otto.oauthtokenfilter.OAuthTokenFilter;
import javax.ws.rs.client.ClientBuilder;
...

ClientBuilder.newBuilder()
  .register(OAuthTokenFilter.builder()
    .username("<yourUsername>")
    .password("<yourPassword>")
    .loginurl("<yourLoginURL>")
    .clientId("<yourClientId>")
    .clientSecret("<yourClientSecret>")
    ...
    .build())
  .build();
```

Depending on your OAuth-service's authentication flow and specifications, you may
need different data. In the ```getOAuth2Token()``` function, you'll find the following code block:

```shell
Form form = new Form();
    form.param("grant_type", "password");
    form.param("username", username);
    form.param("password", password);
    form.param("client_id", clientId);
    form.param("client_secret", clientSecret);
```
You can change those according to your and your service's needs.

## Features

The OAuthTokenProvider filters all server Requests and Responses from and to the client.
By default, the filter() functions work as follows:
* `filter(ClientRequestContext)` adds a Token to every request that the client sends
* `filter(ClientRequestContext, ClientResponseContext)` checks if the server responds with a 
  401 Unauthorized status and resets the token if it does.  
Of course, you can modify those and implement your own logic if you want to!

## Developing

If you'd like to work on the project, you can do so by running: 

```shell
git clone https://github.com/TobiasWaslowski/oauth-token-filter.git
```

If you haven't done so already, you may want to install the Lombok plugin in your IDE.
Visit the following website for more information:
https://projectlombok.org/setup/overview

## Contributing

If you'd like to contribute, please fork the repository and use a feature
branch. Pull requests are warmly welcome.

We're using the GoogleStyle formatting. You can import the following configuration file
into the IDE of your choice:
https://raw.githubusercontent.com/google/styleguide/gh-pages/intellij-java-google-style.xml

## License

The code in this project is licensed under Apache 2.0 license.
