package com.contest_manager.auth_service.service;

import com.contest_manager.auth_service.entity.AuthProvider;
import com.contest_manager.auth_service.entity.Role;
import com.contest_manager.auth_service.entity.User;
import com.contest_manager.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. Let Spring Security fetch the user details from the provider (Google/GitHub/LinkedIn)
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // 2. Which provider is this?
        String provider = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // 3. Extract the email based on the provider's specific JSON structure
        String email = extractEmail(provider, attributes);
        String name = extractName(provider, attributes);

        if (email == null) {
            log.error("OAuth2 provider {} did not return an email address.", provider);
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        // 4. Save or update the user in our PostgreSQL database
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isEmpty()) {
            log.info("Registering new OAuth2 user from {}: {}", provider, email);
            User newUser = User.builder()
                    // If no username is provided, use the first part of the email
                    .username(name != null ? name.replaceAll("\\s+", "").toLowerCase() : email.split("@")[0])
                    .email(email)
                    // OAuth users don't need a local password, but we generate a random dummy one to satisfy DB constraints
                    .password(UUID.randomUUID().toString())
                    .role(Role.USER)
                    .provider(AuthProvider.valueOf(provider.toUpperCase()))
                    .providerId(oAuth2User.getName())
                    .build();
            userRepository.save(newUser);
        } else {
            log.info("Existing user logged in via OAuth2: {}", email);
        }

        return oAuth2User;
    }

    private String extractEmail(String provider, Map<String, Object> attributes) {
        return switch (provider.toLowerCase()) {
            case "google", "github" -> (String) attributes.get("email");
            case "linkedin" -> (String) attributes.get("emailAddress"); // LinkedIn uses a different key
            default -> null;
        };
    }

    private String extractName(String provider, Map<String, Object> attributes) {
        return switch (provider.toLowerCase()) {
            case "google", "github" -> (String) attributes.get("name");
            case "linkedin" -> (String) attributes.get("localizedFirstName") + " " + attributes.get("localizedLastName");
            default -> null;
        };
    }
}