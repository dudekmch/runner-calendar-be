package com.cookieIT.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "application.jwt")
@Component
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterHours;

    public JwtConfig() {
    }


    public String getSecretKey() {
        return secretKey;
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpirationAfterHours() {
        return tokenExpirationAfterHours;
    }

    public void setTokenExpirationAfterHours(Integer tokenExpirationAfterHours) {
        this.tokenExpirationAfterHours = tokenExpirationAfterHours;
    }
}
