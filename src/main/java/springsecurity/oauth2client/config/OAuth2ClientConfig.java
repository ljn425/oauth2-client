package springsecurity.oauth2client.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {
    @Bean
    SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(requests -> requests
                .antMatchers("/", "/oauth2Login","/client").permitAll()
                .anyRequest().authenticated());
//        http.oauth2Login(Customizer.withDefaults()); //클라이언트 인증 및 최종 사용자까지 인증처리하는 API
        http.oauth2Client(Customizer.withDefaults()); // 클라이언트의 인증만 처리하는 API, 최종 사용자 인증 X
        http.logout(logout -> logout.logoutSuccessUrl("/home"));
        return http.build();
    }
}
