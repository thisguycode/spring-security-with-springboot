package com.itchyfingers.springsecurity.filter;

import com.itchyfingers.springsecurity.model.LoginRequest;
import com.itchyfingers.springsecurity.model.LoginResponse;
import com.itchyfingers.springsecurity.util.JsonUtils;
import com.itchyfingers.springsecurity.util.JwtConstants;
import com.itchyfingers.springsecurity.util.JwtUtils;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    log.info("attemptAuthentication");

    try {
      final var body = IOUtils.toString(request.getReader());
      final var loginRequest = JsonUtils.fromJson(LoginRequest.class, body);

      final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
          loginRequest.getUsername(), loginRequest.getPassword()
      );

      setDetails(request, token);

      return this.getAuthenticationManager().authenticate(token);
    } catch (IOException e) {
      log.error("Authentication failed", e);
      throw new InternalAuthenticationServiceException("Authentication failed.", e);
    }
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException {
    log.info("successfulAuthentication");

    final var principal = (User) authResult.getPrincipal();

    final var claims = Jwts.claims().setSubject(principal.getUsername());
    claims.put("authorities", principal.getAuthorities());

    final var jwt = JwtUtils.generateJwt(claims);

    final var responseMsg = LoginResponse.builder()
        .tokenType(JwtConstants.TOKEN_TYPE)
        .token(jwt)
        .build();
    setResponse(response, HttpStatus.OK, responseMsg);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, AuthenticationException failed)
      throws IOException, ServletException {
    log.info("unsuccessfulAuthentication");

    final var message = "Authentication failed. Username or password is incorrect.";
    final var responseMsg = LoginResponse.builder().message(message).build();
    setResponse(response, HttpStatus.UNAUTHORIZED, responseMsg);
  }

  private void setResponse(HttpServletResponse response, HttpStatus status,
      LoginResponse responseMsg)
      throws IOException {
    response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(status.value());
    JsonUtils.writeJson(response.getWriter(), responseMsg);
  }
}
