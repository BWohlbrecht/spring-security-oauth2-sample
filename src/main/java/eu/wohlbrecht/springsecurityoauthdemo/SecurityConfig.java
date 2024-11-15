package eu.wohlbrecht.springsecurityoauthdemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final String spotifyClientId;
	private final String spotifyClientSecret;

	public SecurityConfig(
			@Value("${spotify.clientId}")
			String spotifyClientId,
			@Value("${spotify.clientSecret}")
			String spotifyClientSecret
	) {
		this.spotifyClientId = spotifyClientId;
		this.spotifyClientSecret = spotifyClientSecret;
	}

	// Setting up AuthorizedClientRepository for Login step

	@Bean
	public ClientRegistrationRepository loginRegistrationRepository() {
		ClientRegistration spotifyLogin = ClientRegistration.withRegistrationId("spotify")
				.clientName("Spotify Login")

				.authorizationUri("https://accounts.spotify.com/authorize")
				.tokenUri("https://accounts.spotify.com/api/token")
				.userInfoUri("https://api.spotify.com/v1/me")

				.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")

				.clientId(spotifyClientId)
				.clientSecret(spotifyClientSecret)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)

				.scope("user-read-private", "user-read-email")

				.userNameAttributeName("display_name")

				.build();

		return new InMemoryClientRegistrationRepository(spotifyLogin);
	}

	@Bean
	public OAuth2AuthorizedClientService loginClientService() {
		return new CustomLoggingAuthorizedClientService("Login");
	}

	@Bean
	public OAuth2AuthorizedClientRepository loginClientRepository(OAuth2AuthorizedClientService loginClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(loginClientService);
	}

	// Setting up AuthorizedClientRepository for Authorization step

	@Bean
	public ClientRegistrationRepository authorizationRegistrationRepository() {
		ClientRegistration spotifyLogin = ClientRegistration.withRegistrationId("spotify")
				.clientName("Spotify Client")

				.authorizationUri("https://accounts.spotify.com/authorize")
				.tokenUri("https://accounts.spotify.com/api/token")
				.userInfoUri("https://api.spotify.com/v1/me")

				.redirectUri("{baseUrl}/oauth2/authorized/{registrationId}")

				.clientId(spotifyClientId)
				.clientSecret(spotifyClientSecret)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)

				.scope("playlist-read-private")

				.userNameAttributeName("display_name")

				.build();

		return new InMemoryClientRegistrationRepository(spotifyLogin);
	}

	@Bean
	public OAuth2AuthorizedClientService authorizationClientService() {
		return new CustomLoggingAuthorizedClientService("Authorization");
	}

	@Bean
	public OAuth2AuthorizedClientRepository authorizationClientRepository(OAuth2AuthorizedClientService authorizationClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizationClientService);
	}

	// Configuring the SecurityFilterChain

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
			ClientRegistrationRepository loginRegistrationRepository,
			OAuth2AuthorizedClientRepository loginClientRepository,

			ClientRegistrationRepository authorizationRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizationClientRepository
	) throws Exception {
		return http
				.oauth2Login(login -> {
					login
							.clientRegistrationRepository(loginRegistrationRepository)
							.authorizedClientRepository(loginClientRepository);
				})

				// TODO Add this to see OAuth2LoginAuthenticationFilter switch to client configuration
//				.oauth2Client(client -> {
//					client
//							.clientRegistrationRepository(authorizationRegistrationRepository)
//							.authorizedClientRepository(authorizationClientRepository);
//				})

				.build();
	}

	private static class CustomLoggingAuthorizedClientService implements OAuth2AuthorizedClientService {

		private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

		private final String name;

		private CustomLoggingAuthorizedClientService(String name) {
			this.name = name;
		}

		@Override
		public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
			log.info("Saving authorized client with Service for {}", name);
		}

		@Override
		public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
			log.info("Loading authorized client with Service for {}", name);
			return null;
		}

		@Override
		public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
			// IGNORED
			log.info("Removing authorized client with Service for {}", name);
		}
	}
}
