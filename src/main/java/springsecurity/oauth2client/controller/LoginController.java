package springsecurity.oauth2client.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager authorizedClientManager; // 권한부여 클라이언트 매니저
    private final OAuth2AuthorizedClientRepository authorizedClientRepository; // 권한부여 클라이언트 저장소
    private Duration clockSkew = Duration.ofSeconds(3600);
    private Clock clock = Clock.systemUTC();

    @GetMapping("/oauth2Login")
    public String oauth2Login(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient, Model model) {
        if (authorizedClient != null) {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthorities =
                    authorityMapper.mapAuthorities(oAuth2User.getAuthorities());

            OAuth2AuthenticationToken oAuth2AuthenticationToken =
                    new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, clientRegistration.getRegistrationId());

            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);

            model.addAttribute("AccessToken", authorizedClient.getAccessToken().getTokenValue());
            model.addAttribute("RefreshToken", authorizedClient.getRefreshToken().getTokenValue());
        }
        return "home";
    }

    private boolean hasTokenExpired(OAuth2AccessToken accessToken) {
        return this.clock.instant().isAfter(accessToken.getExpiresAt().minus(this.clockSkew));
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response ) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }


}
