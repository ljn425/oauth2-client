package springsecurity.oauth2client;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(requests -> requests
                .antMatchers("/home").permitAll()
                .anyRequest().authenticated());
        http.oauth2Login(authLogin -> authLogin.authorizationEndpoint(
                authEndpoint -> authEndpoint.authorizationRequestResolver(customOAuthorizationRequestResolver())
        ));
        http.logout(logout -> logout.logoutSuccessUrl("/home"));

        return http.build();
    }

    private OAuth2AuthorizationRequestResolver customOAuthorizationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }
}
