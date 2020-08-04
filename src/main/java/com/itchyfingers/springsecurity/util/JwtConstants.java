package com.itchyfingers.springsecurity.util;

public class JwtConstants {

  public static final String TOKEN_TYPE = "Bearer";
  public static final String TOKEN_PREFIX = TOKEN_TYPE + " ";

  public static final String CLAIMS_AUTHORITIES = "authorities";

  private JwtConstants() {}
}
