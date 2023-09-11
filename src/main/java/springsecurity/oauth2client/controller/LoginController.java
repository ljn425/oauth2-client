package springsecurity.oauth2client.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager authorizedClientManager; // 권한부여 클라이언트 매니저
    private final OAuth2AuthorizedClientRepository authorizedClientRepository; // 권한부여 클라이언트 저장소
    private Duration clockSkew = Duration.ofSeconds(3600);
    private Clock clock = Clock.systemUTC();

    @GetMapping("/oauth2Login")
    public String oauth2Login(HttpServletRequest request, HttpServletResponse response, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // 인증객체 가져오기
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest    // 인증요청 객체 만들기
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        // 권한부여 클라이언트 매니저에게 인증 성공 핸들러를 등록한다.
        OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> authorizedClientRepository
                .saveAuthorizedClient(authorizedClient, principal,
                        (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                        (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));

        authorizedClientManager.setAuthorizationSuccessHandler(successHandler);

        // 인증 요청 객체를 이용해서 권한부여 클라이언트 매니저를 이용해서 권한부여 클라이언트 가져오기
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);

        // 권한부여 타입을 변경하지 않고 실행
        if(authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
            authorizedClientManager.authorize(authorizeRequest);
        }

        // 권한부여 타입을 직접 변경하고 실행
//        if(authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken()) && authorizedClient.getRefreshToken() != null) {
//
//            ClientRegistration clientRegistration = ClientRegistration
//                    .withClientRegistration(authorizedClient.getClientRegistration())
//                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 권한부여 타입 변경 password -> refresh_token
//                    .build();
//
//            OAuth2AuthorizedClient oAuth2AuthorizedClient =
//                    new OAuth2AuthorizedClient(
//                            clientRegistration,
//                            authorizedClient.getPrincipalName(),
//                            authorizedClient.getAccessToken(),
//                            authorizedClient.getRefreshToken()
//                    );
//
//            OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest
//                    .withAuthorizedClient(oAuth2AuthorizedClient)
//                    .principal(authentication)
//                    .attribute(HttpServletRequest.class.getName(), request)
//                    .attribute(HttpServletResponse.class.getName(), response)
//                    .build();
//
//            authorizedClientManager.authorize(oAuth2AuthorizeRequest);
//        }

        if (authorizedClient != null) {
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
