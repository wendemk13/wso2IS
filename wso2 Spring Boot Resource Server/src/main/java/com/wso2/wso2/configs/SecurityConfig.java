//package com.wso2.wso2.configs;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
//import org.springframework.security.oauth2.core.OAuth2TokenValidator;
//import org.springframework.security.oauth2.jwt.*;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
//import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.web.cors.CorsConfiguration;
//import org.springframework.web.cors.CorsConfigurationSource;
//import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.util.Arrays;
//import java.util.Base64;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    private static final String ISSUER_URI = "https://localhost:9443/oauth2/token";
//    private static final String JWKS_URI = "https://localhost:9443/oauth2/jwks";
//
//    @Bean
//    public OncePerRequestFilter jwtDebugFilter() {
//        return new OncePerRequestFilter() {
//            @Override
//            protected void doFilterInternal(HttpServletRequest request,
//                                            HttpServletResponse response,
//                                            FilterChain filterChain) throws ServletException, IOException {
//                String authHeader = request.getHeader("Authorization");
//                if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                    String token = authHeader.substring(7);
//                    try {
//                        String[] parts = token.split("\\.");
//                        if (parts.length >= 2) {
//                            Base64.Decoder decoder = Base64.getUrlDecoder();
//                            String headerJson = new String(decoder.decode(parts[0]));
//                            String payloadJson = new String(decoder.decode(parts[1]));
//                            System.out.println("===== JWT Debug =====");
//                            System.out.println("Header: " + headerJson);
//                            System.out.println("Payload: " + payloadJson);
//                        }
//                    } catch (Exception e) {
//                        System.out.println("Failed to decode JWT: " + e.getMessage());
//                    }
//                }
//                filterChain.doFilter(request, response);
//            }
//        };
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        http
//                // Add debug filter before Spring Security
//                .addFilterBefore(jwtDebugFilter(),
//                        org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
//                .csrf(csrf -> csrf.disable())
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
//                .authorizeHttpRequests(auth -> auth
//                        // Public endpoints
//                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
//                        .requestMatchers("/actuator/health", "/public/**", "/error").permitAll()
//                        // Protected endpoints
//                        .requestMatchers("/students").authenticated()
//                        .requestMatchers("/students/**").hasRole("ADMIN")
//                        // All other endpoints require authentication
//                        .anyRequest().authenticated()
//                )
//                // OAuth2 Resource Server to validate JWT tokens
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
//                );
//
//        return http.build();
//    }
//
//    @Bean
//    public JwtAuthenticationConverter jwtAuthenticationConverter() {
//        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        grantedAuthoritiesConverter.setAuthoritiesClaimName("http://wso2.org/claims/role"); // WSO2 roles claim
//        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
//
//        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
//        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
//
//        return converter;
//    }
//
//
//    @Bean
//    public JwtDecoder jwtDecoder() {
//        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWKS_URI).build();
//
//        // 1. Create a custom validator that accepts both "JWT" and "at+jwt"
//        // This addresses the strict header check from your logs.
//        OAuth2TokenValidator<Jwt> typValidator = new JwtClaimValidator<String>(
//                "typ",
//                typ -> typ == null || typ.equals("JWT") || typ.equals("at+jwt")
//        );
//
//        // 2. Add standard validators (Issuer and Timestamp)
//        // NOTE: ISSUER_URI must match "https://localhost:9443/oauth2/token" exactly
//        OAuth2TokenValidator<Jwt> issuerValidator = new JwtIssuerValidator(ISSUER_URI);
//        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();
//
//        // 3. Chain them together using DelegatingOAuth2TokenValidator
//        // This REPLACES the default Spring validators entirely.
//        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(
//                issuerValidator,
//                timestampValidator,
//                typValidator
//        );
//
//        jwtDecoder.setJwtValidator(combinedValidator);
//        return jwtDecoder;
//    }
//
//
//
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.setAllowedOrigins(Arrays.asList(
//                "http://localhost:3000", // frontend dev
//                "https://localhost:9443" // WSO2 console / JWKS
//        ));
//        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
//        configuration.setAllowCredentials(true);
//        configuration.setMaxAge(3600L);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }
//}




package com.wso2.wso2.configs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wso2.wso2.dto.CustomErrorResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String ISSUER_URI = "https://localhost:9443/oauth2/token";
    private static final String JWKS_URI = "https://localhost:9443/oauth2/jwks";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .addFilterBefore(jwtDebugFilter(), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/actuator/health", "/public/**", "/error").permitAll()
                        .requestMatchers("/students").authenticated()
                        .requestMatchers("/students/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder()) // Force use of custom decoder
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                        // Inline Exception Handling
                        .authenticationEntryPoint(customAuthenticationEntryPoint()) // Handles 401
                        .accessDeniedHandler(customAccessDeniedHandler())           // Handles 403
                );

        return http.build();
    }

    // 401 Unauthorized Handler (Invalid/Missing Token)
    @Bean
    public AuthenticationEntryPoint customAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            CustomErrorResponse error = new CustomErrorResponse(
                    HttpStatus.UNAUTHORIZED.value(),
                    "Unauthorized",
                    authException.getMessage() // Will show "typ needs to be one of [JWT]" if decoder fails
            );

            new ObjectMapper().writeValue(response.getOutputStream(), error);
        };
    }

    // 403 Forbidden Handler (Insufficient Roles)
    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            CustomErrorResponse error = new CustomErrorResponse(
                    HttpStatus.FORBIDDEN.value(),
                    "Forbidden",
                    "You do not have the required ADMIN role to access this resource."
            );

            new ObjectMapper().writeValue(response.getOutputStream(), error);
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWKS_URI).build();

        // Fix for WSO2 7.0 'at+jwt' type error
        OAuth2TokenValidator<Jwt> typValidator = new JwtClaimValidator<String>(
                "typ",
                typ -> typ == null || typ.equals("JWT") || typ.equals("at+jwt")
        );

        OAuth2TokenValidator<Jwt> issuerValidator = new JwtIssuerValidator(ISSUER_URI);
        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();

        // Replace the entire validation chain to exclude the default strict typ validator
        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(
                issuerValidator,
                timestampValidator,
                typValidator
        );

        jwtDecoder.setJwtValidator(combinedValidator);
        return jwtDecoder;
    }

//    @Bean
//    public JwtAuthenticationConverter jwtAuthenticationConverter() {
//        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
//        grantedAuthoritiesConverter.setAuthoritiesClaimName("http://wso2.org/claims/role");
//        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
//
//        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
//        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
//        return converter;
//    }

    @Bean
    public OncePerRequestFilter jwtDebugFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7);
                    try {
                        String[] parts = token.split("\\.");
                        if (parts.length >= 2) {
                            Base64.Decoder decoder = Base64.getUrlDecoder();
                            System.out.println("===== JWT Debug =====");
                            System.out.println("Header: " + new String(decoder.decode(parts[0])));
                            System.out.println("Payload: " + new String(decoder.decode(parts[1])));
                        }
                    } catch (Exception ignored) {}
                }
                filterChain.doFilter(request, response);
            }
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://localhost:9443"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }


    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // 1. Specify the WSO2 Role Claim
        grantedAuthoritiesConverter.setAuthoritiesClaimName("http://wso2.org/claims/role");

        // 2. Set the Prefix to ROLE_
        // This means "admin" becomes "ROLE_admin"
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Get original authorities (e.g., ROLE_admin, ROLE_manager)
            var authorities = grantedAuthoritiesConverter.convert(jwt);

            // 3. Force to Uppercase to match .hasRole("ADMIN")
            // This ensures ROLE_admin matches ROLE_ADMIN
            return authorities.stream()
                    .map(authority -> new org.springframework.security.core.authority.SimpleGrantedAuthority(
                            authority.getAuthority().toUpperCase()))
                    .collect(java.util.stream.Collectors.toList());
        });

        return converter;
    }

}
