package com.work.springsecuritytut.Security;

import com.work.springsecuritytut.entity.Role;
import org.apache.tomcat.websocket.AuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Component
public class JwtGenerator {

    // czas zycia tokenu
    private final long JWT_EXPIRATION = 7000;
    //zastosowwany algorytm
    private final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;
    //klucz prywatny
    private final String JWT_SECRET = "ThisIsAStrongKeyForJwtEncryptionYouCanCreateAnyStrongKeyHereButMustBeMoreThan256BitsLength\"";

    private final JWSSigner signer;
    private final JWSVerifier verifier;

    public JwtGenerator() {
        try {
            signer = new MACSigner(JWT_SECRET.getBytes());
            verifier = new MACVerifier(JWT_SECRET.getBytes());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

    }

    public String generateToknen(String username, List<String> roles) {

        JWSHeader header = new JWSHeader(jwsAlgorithm);

        LocalDateTime nowPlus1Hours = LocalDateTime.now().plusSeconds(JWT_EXPIRATION);

        //wygasniecie tokana
        Date expirationDate = Date.from(nowPlus1Hours.atZone(ZoneId.systemDefault()).toInstant());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .expirationTime(expirationDate)
                .claim("role", roles)//niestandardowe roszczenia
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);// tworzenie tokena

        // podpisanie tokenu
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT.serialize();
    }

    void verifySignature(SignedJWT signedJWT) {
        try {
            //sprawdzenie poprwnosci tokena
            boolean verifed = signedJWT.verify(verifier);
            if (!verifed) {
                throw new RuntimeException("Invalid signature");
            }

        } catch (JOSEException e){
            throw new RuntimeException("Fail signature");
        }
    }

    void verifyExpirationTime(SignedJWT signedJWT) {
        try {
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            LocalDateTime expirationDateTime = jwtClaimsSet
                    .getDateClaim("exp")
                    .toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();
            if (LocalDateTime.now().isAfter(expirationDateTime)) {
                throw new JwtAuthenticationException("Token Expired at %s".formatted(expirationDateTime));
            }
        } catch (ParseException e) {
            throw new JwtAuthenticationException("Token does not have exp claim");
        }
    }


    public Authentication createAuthentication(SignedJWT signedJWT) {
        String subject;
        List<String> authorities;
        try {
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            subject = jwtClaimsSet.getSubject();
            if (jwtClaimsSet.getClaim("authorities") != null) {
                authorities = jwtClaimsSet.getStringListClaim("authorities");
            } else {
                return new UsernamePasswordAuthenticationToken(subject, null, Collections.emptyList());
            }
        } catch (ParseException e) {
            throw new RuntimeException("Missing claims sub or authorities");
        }
        List<SimpleGrantedAuthority> grantedAuthorities = authorities.stream().map(SimpleGrantedAuthority::new).toList();
        return new UsernamePasswordAuthenticationToken(subject, null, grantedAuthorities);
    }
    public String getEmailFromToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            return jwtClaimsSet.getSubject();
        } catch (ParseException e){
            throw new JwtAuthenticationException("Failed to get email from token");
        }
    }
}
