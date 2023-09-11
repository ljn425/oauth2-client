package springsecurity.oauth2client.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import springsecurity.oauth2client.filter.CustomOAuth2AuthenticationFilter;

import javax.servlet.Filter;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final DefaultOAuth2AuthorizedClientManager authorizedClientManager; // 권한부여 클라이언트 매니저
    private final OAuth2AuthorizedClientRepository authorizedClientRepository; // 권한부여 클라이언트 저장소

    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(requests -> requests
                .antMatchers("/", "/oauth2Login","/client").permitAll()
                .anyRequest().authenticated());
        http.oauth2Client(Customizer.withDefaults()); // 클라이언트의 인증만 처리하는 API, 최종 사용자 인증 X
        http.logout(logout -> logout
                .logoutSuccessUrl("/home")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true));
        http.addFilterBefore(customOAuth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    private CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() {
        CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter =
                new CustomOAuth2AuthenticationFilter(authorizedClientManager, authorizedClientRepository);

        customOAuth2AuthenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            response.sendRedirect("/home");
        });
        return customOAuth2AuthenticationFilter;
    }
}
