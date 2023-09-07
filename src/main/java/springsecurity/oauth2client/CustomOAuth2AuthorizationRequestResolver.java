package springsecurity.oauth2client;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private static final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
            .withPkce();
    private ClientRegistrationRepository clientRegistrationRepository;
    DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    private final AntPathRequestMatcher authorizationRequestMatcher;


    public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {

        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(
                authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");

        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request); // registrationId를 가져온다.
        if (registrationId == null) {
            return null;
        }
        if(registrationId.equals("keycloakWithPKCE")){
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request); // 기본 resolver 로 OAuth2AuthorizationRequest 를 가져온다.
            return customResolve(oAuth2AuthorizationRequest);

        }
        return defaultResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        if(clientRegistrationId.equals("keycloakWithPKCE")){
            OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request);
            return customResolve(oAuth2AuthorizationRequest);
        }
        return defaultResolver.resolve(request,clientRegistrationId);
    }
    private OAuth2AuthorizationRequest customResolve(OAuth2AuthorizationRequest oAuth2AuthorizationRequest) {
//
        Map<String,Object> extraParam = new HashMap<>();
        extraParam.put("customName1","customValue1");
        extraParam.put("customName2","customValue2");
        extraParam.put("customName3","customValue3");

        OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
                .from(oAuth2AuthorizationRequest) // 기존의 OAuth2AuthorizationRequest 를 가져와서 builder에 넣는다.
                .additionalParameters(extraParam);
        
        DEFAULT_PKCE_APPLIER.accept(builder); // builder에 pkce관련 코드를 추가한다.

        return builder.build();
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.authorizationRequestMatcher.matches(request)) { // uri 가 /oauth2/authorization/{registrationId} 와 일치하는지 확인
            return this.authorizationRequestMatcher.matcher(request).getVariables() // 일치하면 registrationId를 가져온다.
                    .get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }
}
