package com.work.springsecuritytut.Security;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.text.ParseException;

public class BearerTokenFilter extends HttpFilter {
    private final Logger logger = LoggerFactory.getLogger(BearerTokenFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private final SecurityContextHolderStrategy securityContextHolderStrategy =
            SecurityContextHolder.getContextHolderStrategy();
    private final AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    private final JwtGenerator jwtGenerator;

    public BearerTokenFilter(JwtGenerator jwtGenerator) {
        this.jwtGenerator= jwtGenerator;
    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response,
                            FilterChain chain)
            throws IOException, ServletException {

        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            logger.debug("Missing Authorization header or empty Bearer token");
            chain.doFilter(request, response);
        } else {
            String compactJwt = authorizationHeader.substring(BEARER_PREFIX.length());
            SignedJWT signedJwt;
            try {
                signedJwt = SignedJWT.parse(compactJwt);
                verifyJwt(signedJwt);
                setSecurityContext(signedJwt);
                chain.doFilter(request, response);
            } catch (JwtAuthenticationException e) {
                logger.debug(e.getMessage());
                failureHandler.onAuthenticationFailure(request, response, e);
            } catch (ParseException e) {
                JwtAuthenticationException authException = new JwtAuthenticationException("Bearer token could not be parsed");
                logger.debug(e.getMessage());
                failureHandler.onAuthenticationFailure(request, response, authException);
            }
        }
    }

    private void setSecurityContext(SignedJWT signedJwt) {
        Authentication authentication = jwtGenerator.createAuthentication(signedJwt);
        SecurityContext securityContext = securityContextHolderStrategy.getContext();
        securityContext.setAuthentication(authentication);
    }

    private void verifyJwt(SignedJWT signedJwt) {
        jwtGenerator.verifySignature(signedJwt);
        jwtGenerator.verifyExpirationTime(signedJwt);
    }
}


