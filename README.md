* Provide a spotify.clientId and spotify.secret for Spotify or replace Spotify with any other service.
* Run the application and debug into OAuth2LoginAuthenticationFilter.
* Observe the correct ClientRegistrationRepository and OAuth2AuthorizedClientRepository are present.
* Add the commented section for oAuth2Client configuration
* Run the application again and debug into OAuth2LoginAuthenticationFilter.
* Observe the wrong instances of ClientRegistrationRepository and OAuth2AuthorizedClientRepository are present.
