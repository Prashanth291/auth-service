package com.contest_manager.auth_service.config;

import com.contest_manager.auth_service.security.OAuth2LoginSuccessHandler;
import com.contest_manager.auth_service.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Disable CSRF (Safe to do because we are using stateless JWTs, not cookies)
                .csrf(csrf -> csrf.disable())

                // 2. Enable CORS so React/Next.js frontend can talk to this API
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // 3. Make the session STATELESS. Spring Security won't create a JSESSIONID.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 4. Secure the routes
                .authorizeHttpRequests(auth -> auth
                        // Allow anyone to hit the login endpoints and error pages
                        .requestMatchers("/", "/login/**", "/oauth2/**", "/error").permitAll()
                        // Require authentication for literally everything else
                        .anyRequest().authenticated()
                )

                // 5. Wire up our Custom OAuth2 logic
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler(oAuth2LoginSuccessHandler)
                );

        return http.build();
    }

    // Tells the browser it is okay for the frontend to request data from this backend
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000")); // Your frontend URL
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}