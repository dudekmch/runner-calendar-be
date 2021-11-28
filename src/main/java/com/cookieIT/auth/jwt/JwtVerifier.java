package com.cookieIT.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
        if (Strings.isEmpty(authHeader) || !authHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = createAuthenticationFromHeader(authHeader);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e) {
            throw new IllegalStateException("Token cannot be truest: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    @SuppressWarnings("unchecked")
    private Authentication createAuthenticationFromHeader(String header) {
        String token = header.replace(jwtConfig.getTokenPrefix(), Strings.EMPTY);
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token);

        String userName = claimsJws.getBody().getSubject();
        List<Map<String, String>> authorities =
                (List<Map<String, String>>) claimsJws.getBody().get("authorities");

        Set<SimpleGrantedAuthority> grantedAuthorities =
                authorities.stream()
                        .map(authority -> new SimpleGrantedAuthority(authority.get("authority")))
                        .collect(Collectors.toSet());

        return new UsernamePasswordAuthenticationToken(
                userName,
                null,
                grantedAuthorities
        );
    }
}
