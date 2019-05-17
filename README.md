# OAuthTokenFilter

If you're working with a service that uses OAuth2 for authentication, 
you can use the OAuthTokenFilter for automatic authentication.
It filters your requests to that service, caches your OAuth-Token, 
checks it for validity and refreshes it when necessary. 

## Installing / Getting started

To include the OAuthTokenFilter in your project, simpy add it as a Maven Dependency. 

```shell
<groupId>de.otto.oauthtokenfilter</groupId>
  <artifactId>oauth-token-filter</artifactId>
  <version>1.0</version>
  ```

### Initial Configuration

Upon using your ClientBuilder, call 
```shell
import OAuthTokenFilter;
...

ClientBuilder.newBuilder()
  .register(OAuthTokenFilter.builder()
    .username("<yourUsername>")
    .password("<yourPassword>")
    ...
    .build())
  .build();
```

## Features

The OAuthTokenProvider filters all server Requests and Responses from and to the client.
By default, the filter() functions work as follows:
* filter(ClientRequestContext) adds a Token to every request that the client sends
* filter(ClientRequestContext, ClientResponseContext) checks if the server responds with a 
  401 Unauthorized and resets the token if it does.

## Developing

If you'd like to work on the project, you can do so by running: 

```shell
git clone https://github.com/TobiasWaslowski/oauth-token-filter.git
```

## Contributing

If you'd like to contribute, please fork the repository and use a feature
branch. Pull requests are warmly welcome.

We're using the GoogleStyle formatting. You can import the following configuration file
into the IDE of your choice:
https://raw.githubusercontent.com/google/styleguide/gh-pages/intellij-java-google-style.xml

## Licensing

The code in this project is licensed under Apache 2.0 license.
