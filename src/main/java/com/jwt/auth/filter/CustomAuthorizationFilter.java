package com.jwt.auth.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@Log4j2
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("Authorization Filter - START");

        String requestedPath = request.getServletPath();
        log.info("Requested Path : {}", requestedPath);

        if (requestedPath.equals("/auth/getToken")) {
            log.info("Requesting Token.. Passing to Authentication Filter");
            filterChain.doFilter(request, response);
        } else {

            log.info("Verifying Auth Token");
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header != null && !header.isBlank() && !header.isEmpty()) {
                if (header.startsWith("Bearer ")) {
                    try {
                        String token = header.substring("Bearer ".length());
                        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                        // Token Verification
                        JWTVerifier verifier = JWT.require(algorithm).build();
                        DecodedJWT decodedJwt = verifier.verify(token);

                        // Decoded JWT
                        String userName = decodedJwt.getSubject();
                        Claim claims = decodedJwt.getClaim("Roles");
                        String[] roles = claims.asArray(String.class);
                        List<GrantedAuthority> authorities = new ArrayList<>();
                        for (String role : roles) {
                            authorities.add(new SimpleGrantedAuthority(role));
                        }

                        // Set Token
                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(userName, "", authorities);
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                        // Pass the request after setting to security context
                        filterChain.doFilter(request, response);

                    } catch (Exception e) {
                        log.error("Exception Occurred in Authorization layer {}", e.getMessage());
                        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                        response.setStatus(HttpStatus.FORBIDDEN.value());

                        Map<String, String> tokens = new HashMap<>();
                        tokens.put("error", e.getMessage());
                        tokens.put("message", "Exception during Authorization");
                        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
                    }
                }
            } else {
                log.error("Invalid Authorization");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setStatus(HttpStatus.FORBIDDEN.value());

                Map<String, String> tokens = new HashMap<>();
                tokens.put("message", "Invalid Authorization Value");
                new ObjectMapper().writeValue(response.getOutputStream(), tokens);
            }
        }

        log.info("Authorization Filter - END");
    }
}
