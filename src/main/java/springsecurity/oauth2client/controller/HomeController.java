package springsecurity.oauth2client.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class HomeController {
    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/home")
    public String home(OAuth2AuthenticationToken oAuth2AuthenticationToken, Model model) {
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient("keycloak", oAuth2AuthenticationToken.getName());
        model.addAttribute("AccessToken", authorizedClient.getAccessToken().getTokenValue());
        model.addAttribute("RefreshToken", authorizedClient.getRefreshToken().getTokenValue());



        return "home";
    }
}
