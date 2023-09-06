package springsecurity.oauth2client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class OAuth2ClientConfig {

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(requests -> requests
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated());
        http.oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
//                        .loginProcessingUrl("/login/oauth2/code/*") // redirectionEndPoint 설정과 같은 역할은 하는데 redirectionEndPoint가 우선순위가 높음
                .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig
                        .baseUri("/oauth2/v1/authorization")
                        // 클라이언트가 인가서버에 authorization code를 요청할 때 사용하는 endpoint custom
                        // default OAuth2AuthorizationRequestRedirectFilter -> /oauth2/authorization
                )
                .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig
                        .baseUri("/login/v1/oauth2/code/*")) // default OAuth2LoginAuthenticationFilter -> /login/oauth2/code/*

                );

        return http.build();
    }
}
