package com.itchyfingers.springsecurity.filter;

import com.itchyfingers.springsecurity.exception.ApplicationException;
import com.itchyfingers.springsecurity.util.JwtConstants;
import com.itchyfingers.springsecurity.util.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
public class JwtVerificationFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    log.info("doFilterInternal");

    final var jwtToken = getJwtToken(request);
    log.info("doFilterInternal - jwtToken:{}", jwtToken.orElse("Empty Token"));
    if (jwtToken.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }

    try {
      final var claims = JwtUtils.parseJwt(jwtToken.get());
      final UsernamePasswordAuthenticationToken authentication = getUsernamePasswordAuthenticationToken(
          claims);
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (JwtException e) {
      throw new ApplicationException("Invalid JWT Token", e);
    }
    filterChain.doFilter(request, response);
  }

  private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(
      Claims claims) {
    final var username = claims.getSubject();
    final var authorities = (List<Map<String, String>>) claims.get(JwtConstants.CLAIMS_AUTHORITIES);
    final var simpleGrantedAuthorities = authorities.stream()
        .map(m -> new SimpleGrantedAuthority(m.get("authority")))
        .collect(Collectors.toSet());

    return new UsernamePasswordAuthenticationToken(
        username, null, simpleGrantedAuthorities);
  }

  private Optional<String> getJwtToken(HttpServletRequest request) {
    final var authenticationHeader = request.getHeader("Authentication");
    log.info("getJwtToken - authenticationHeader:{}", authenticationHeader);
    final var token = StringUtils.substringAfter(authenticationHeader, JwtConstants.TOKEN_PREFIX);
    return Optional.ofNullable(token);
  }
}
