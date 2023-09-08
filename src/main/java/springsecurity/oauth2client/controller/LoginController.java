package springsecurity.oauth2client.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager authorizedClientManager; // 권한부여 클라이언트 매니저
    private final OAuth2AuthorizedClientRepository authorizedClientRepository; // 권한부여 클라이언트 저장소

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

//        if(authorizedClient != null) { // 인증객체가 존재하면 최종사용자 인증 처리
//            OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest( // 최종사용자 인증 요청 객체 만들기
//                    authorizedClient.getClientRegistration(),
//                    authorizedClient.getAccessToken()
//            );
//
//            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
//            OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest); // 인가서버에서 최종사용자 정보 가져오기
//
//            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
//            authorityMapper.setPrefix("SYSTEM_"); // 권한부여 클라이언트에서 가져온 권한에 SYSTEM_ 접두어 붙이기
//            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities()); // 최종사용자 권한 가져오기
//
//            OAuth2AuthenticationToken oAuth2AuthenticationToken =
//                    new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, authorizedClient.getClientRegistration().getRegistrationId());// 최종사용자 인증객체 만들기
//
//            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken); // 최종사용자 인증객체 저장하기
//
//            model.addAttribute("oAuth2AuthenticationToken", oAuth2AuthenticationToken);
//        }
        if (authorizedClient != null)
            model.addAttribute("oAuth2AuthenticationToken", authorizedClient.getAccessToken().getTokenValue());

        return "home";
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response ) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }


}
