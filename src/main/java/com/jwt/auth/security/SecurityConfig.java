package com.jwt.auth.security;

import com.jwt.auth.filter.CustomAuthenticationFilter;
import com.jwt.auth.filter.CustomAuthorizationFilter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Log4j2
public class SecurityConfig {

    @Lazy
    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean
    public SecurityFilterChain httpSecurity(HttpSecurity httpSecurity) throws Exception {

        log.info("Security Filter Chain - START");
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager);
        customAuthenticationFilter.setFilterProcessesUrl("/auth/getToken");

        // Disable Cross-site-request-forgery attack
        httpSecurity.csrf().disable();

        // Disable STATEFUL session management - To avoid managing user login session states
        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // add Filter
        httpSecurity.addFilter(customAuthenticationFilter);
        httpSecurity.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        // Permit all requests
        return httpSecurity
                .authorizeHttpRequests((authorize) -> {
                    authorize.antMatchers("/auth/test/**").permitAll();
                    authorize.antMatchers(HttpMethod.GET, "/auth/users/**").permitAll();
                    authorize.antMatchers(HttpMethod.POST, "/auth/users/**").hasAuthority("ROLE_SUPER_ADMIN");
                    authorize.antMatchers(HttpMethod.POST, "/auth/roles/").hasAuthority("ROLE_ADMIN");
                    authorize.antMatchers(HttpMethod.POST, "/auth/roles/add").hasAuthority("ROLE_MANAGER");
                    authorize.anyRequest().authenticated();
                }).build();
    }
}
