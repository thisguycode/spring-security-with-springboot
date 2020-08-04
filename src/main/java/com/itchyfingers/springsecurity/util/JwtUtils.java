package com.itchyfingers.springsecurity.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Duration;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtUtils {

  private static final String DEFAULT_SECRET = "December 2020 will be my last month in the current project";
  private static final Duration DEFAULT_EXPIRATION = Duration.ofMinutes(10);

  private static Key getSecretKey() {
    final var secretKey = Keys.hmacShaKeyFor(DEFAULT_SECRET.getBytes(StandardCharsets.UTF_8));
    return secretKey;
  }

  public static String generateJwt(Claims claims) {
    final var secretKey = getSecretKey();
    return Jwts.builder()
        .setId(UUID.randomUUID().toString())
        .setClaims(claims)
        .setIssuedAt(DateUtils.now())
        .setExpiration(DateUtils.nowPlus(DEFAULT_EXPIRATION))
        .signWith(secretKey).compact();
  }

  public static Claims parseJwt(String jwt) {
    final var secretKey = getSecretKey();
    return Jwts.parserBuilder()
        .setSigningKey(secretKey).build()
        .parseClaimsJws(jwt).getBody();
  }
}
