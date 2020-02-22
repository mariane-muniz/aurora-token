package com.omni.aurora.token.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.omni.aurora.core.model.ApplicationUser;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class SecurityContextUtil {

    SecurityContextUtil(){
    }

    public static void setSecurityContext(final SignedJWT signedJWT) {
        try {
            final JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            final String username = claims.getSubject();
            if (StringUtils.isEmpty(username))
                throw new JOSEException("Username missing from JWT");
            final List<String> authorities = claims.getStringListClaim("authorities");
            final ApplicationUser applicationUser = ApplicationUser
                    .builder()
                    .id(claims.getLongClaim("userId"))
                    .username(username)
                    .role(String.join(",", authorities))
                    .build();
            final UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
              applicationUser, null, createAuthorities(authorities)
            );
            auth.setDetails(signedJWT.serialize());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        catch (Exception e) {
            log.error("Error settings security context", e);
            SecurityContextHolder.clearContext();
        }
    }

    private static List<SimpleGrantedAuthority> createAuthorities(final List<String> authorities) {
        return authorities.parallelStream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}
