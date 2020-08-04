package com.itchyfingers.springsecurity.util;

import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DateUtils {

  public static java.util.Date now() {
    return Date.from(Instant.now());
  }

  public static java.util.Date nowPlus(Duration duration) {
    final var instant = Instant.now().plusSeconds(duration.getSeconds());
    return Date.from(instant);
  }
}
