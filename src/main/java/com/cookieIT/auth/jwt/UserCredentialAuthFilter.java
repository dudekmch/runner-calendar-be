package com.cookieIT.auth.jwt;

import com.cookieIT.auth.jwt.model.UserCredentialAuthRequest;
import com.cookieIT.auth.jwt.model.exception.ParsingUserCredentialException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class UserCredentialAuthFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public UserCredentialAuthFilter(AuthenticationManager authenticationManager,
                                    SecretKey secretKey,
                                    JwtConfig jwtConfig) {
        this.authenticationManager = authenticationManager;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            UserCredentialAuthRequest authRequest =
                    new ObjectMapper()
                            .readValue(request.getInputStream(), UserCredentialAuthRequest.class);
            return authenticationManager.authenticate(createAuthenticationToken(authRequest));
        } catch (IOException e) {
            throw new ParsingUserCredentialException("Error parsing request to object");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(Date.from(LocalDateTime.now()
                        .plusHours(jwtConfig.getTokenExpirationAfterHours())
                        .atZone(ZoneId.systemDefault())
                        .toInstant()))
                .signWith(secretKey)
                .compact();

        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
    }

    private Authentication createAuthenticationToken(UserCredentialAuthRequest authRequest) {
        return new UsernamePasswordAuthenticationToken(
                authRequest.getUsername(),
                authRequest.getPassword()
        );
    }
}
