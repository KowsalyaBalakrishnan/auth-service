package com.jwt.auth.service.impl.security;

import com.jwt.auth.domain.AppUser;
import com.jwt.auth.repo.UserRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@Log4j2
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        log.info("UserDetailsServiceImpl - loadUserByUsername - START");

        // Get user details from database
        AppUser appUserDetails = userRepository.findByUserName(username);
        if (appUserDetails != null) {
            log.info("DB Fetched User = {} , {}",
                    appUserDetails.getUserName(), appUserDetails.getPassword());
        }

        // Convert roles to Authorities
        List<SimpleGrantedAuthority> authorities = List.of();
        if (appUserDetails.getUserRoles() != null) {
           authorities = appUserDetails.getUserRoles()
                    .stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList());
        }


        // Return the user object
        User user = new User(appUserDetails.getUserName(), appUserDetails.getPassword(), authorities);
        if (user.getUsername() != null && user.getPassword() != null) {
            log.info("UserName {} ", user.getUsername());
            log.info("Password {}", user.getPassword());
        }
        log.info("UserDetailsServiceImpl - loadUserByUsername - END");

        return user;

    }
}
