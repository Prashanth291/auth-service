package com.contest_manager.auth_service.security;

import com.contest_manager.auth_service.entity.User;
import com.contest_manager.auth_service.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // Grab the email provided by Google/GitHub
        String email = oAuth2User.getAttribute("email");

        // Find the user we just saved in CustomOAuth2UserService
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found after OAuth login"));

        // Generate the JWT!
        String token = jwtService.generateToken(user);

        log.info("Successfully generated JWT for user: {}", email);

        // Redirect the user back to the React/Next.js frontend with the token in the URL
        // Your friend's frontend will grab this token from the URL and save it to LocalStorage
        String frontendUrl = "http://localhost:3000/oauth2/redirect?token=" + token;

        getRedirectStrategy().sendRedirect(request, response, frontendUrl);
    }
}