package com.cookieIT.auth.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Collections;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoImpl implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    private static class Grants implements GrantedAuthority {

        protected Grants() {}

        @Override
        public String getAuthority() {
            return "test_login";
        }
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return Optional.of(new ApplicationUser(
                Collections.singletonList(new Grants()),
                passwordEncoder.encode("abc"),
                "pawel",
                true,
                true,
                true,
                true));
    }
}
