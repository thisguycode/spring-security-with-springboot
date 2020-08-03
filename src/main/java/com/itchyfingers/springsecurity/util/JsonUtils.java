package com.itchyfingers.springsecurity.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.itchyfingers.springsecurity.exception.ApplicationException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JsonUtils {

  public static <T> T fromJson(Class<T> type, String json) {
    log.info("fromJson - type:{}, json:{}", type, json);

    try {
      ObjectMapper objectMapper = new ObjectMapper();
      return objectMapper.readValue(json, type);
    } catch (JsonProcessingException e) {
      throw new ApplicationException("Failed to parse json", e);
    }
  }

  public static <T> T fromJson(Class<T> type, InputStream inputStream) {
    log.info("fromJson - type:{}", type);

    try {
      ObjectMapper objectMapper = new ObjectMapper();
      return objectMapper.readValue(inputStream, type);
    } catch (IOException e) {
      throw new ApplicationException("Failed to parse json", e);
    }
  }

  public static <T> void writeJson(Writer writer, Object object) {
    log.info("writeJson - object:{}", object);

    try {
      ObjectMapper objectMapper = new ObjectMapper();
      objectMapper.writeValue(writer, object);
    } catch (IOException e) {
      throw new ApplicationException("Failed to write json", e);
    }
  }
}
