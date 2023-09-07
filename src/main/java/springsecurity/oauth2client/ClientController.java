package springsecurity.oauth2client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Objects;

@Controller
@RequiredArgsConstructor
public class ClientController {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/client")
    public String client(HttpServletRequest request, Model model) {
        // 인증객체 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String clientRegistrationId = "keycloak";

        // 등록된 클라이언트 정보 가져오기
        OAuth2AuthorizedClient oAuth2AuthorizedClient1 = authorizedClientRepository
                .loadAuthorizedClient(clientRegistrationId, authentication, request);

        OAuth2AuthorizedClient oAuth2AuthorizedClient2 = authorizedClientService
                .loadAuthorizedClient(clientRegistrationId, authentication.getName());

        OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();

        // 인가서버에 접근해서 최종 사용자 정보 가져오기
        OAuth2AccessToken accessToken = oAuth2AuthorizedClient1.getAccessToken();
        OAuth2User oAuth2User = oAuth2UserService.loadUser(new OAuth2UserRequest(
                oAuth2AuthorizedClient1.getClientRegistration(),
                accessToken)
        );

        // 최종 사용자 정보를 이용해서 인증객체 만들기
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
                oAuth2User,
                List.of(new SimpleGrantedAuthority("ROLE_USER")),
                clientRegistrationId
        );

        // 인증객체 저장
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        model.addAttribute("accessToken", accessToken.getTokenValue());
        model.addAttribute("refreshToken", Objects.requireNonNull(oAuth2AuthorizedClient1.getRefreshToken()).getTokenValue());
        model.addAttribute("principalName", oAuth2User.getName());
        model.addAttribute("clientName", oAuth2AuthorizedClient1.getClientRegistration().getClientName());

        return "client";
    }
}
