package com.omni.aurora.token.filter;

import com.nimbusds.jwt.SignedJWT;
import com.omni.aurora.core.property.JWTConfiguration;
import com.omni.aurora.token.converter.TokenConverter;
import com.omni.aurora.token.util.SecurityContextUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.equalsIgnoreCase;

@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JwtTokenAuthorizationFilter extends OncePerRequestFilter {

    private final JWTConfiguration jwtConfiguration;
    protected final TokenConverter tokenConverter;

    @Override
    protected void doFilterInternal(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final FilterChain filterChain)
            throws ServletException, IOException {
        final String header = request.getHeader(this.jwtConfiguration.getHeader().getName());
        if (StringUtils.isEmpty(header) || !header.startsWith(this.jwtConfiguration.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }
        final String token = header.replace(this.jwtConfiguration.getHeader().getPrefix(), "").trim();
        SecurityContextUtil.setSecurityContext(
                equalsIgnoreCase("signed", this.jwtConfiguration.getType()) ? validate(token) : decryptValidating(token));
        filterChain.doFilter(request, response);
    }


    @SneakyThrows
    private SignedJWT decryptValidating(String encryptedToken) {
        String signedToken = tokenConverter.decryptToken(encryptedToken);
        tokenConverter.validateTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(String signedToken) {
        tokenConverter.validateTokenSignature(signedToken);
        return SignedJWT.parse(signedToken);
    }
}
