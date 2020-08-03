package com.itchyfingers.springsecurity.controller;

import com.itchyfingers.springsecurity.model.MessageResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/messages")
public class MessageController {

  @GetMapping("/public")
  public MessageResponse publicMessage() {
    final var message = "Hello, this is anonymous message";
    return new MessageResponse(message);
  }

  @GetMapping("/private")
  public MessageResponse privateMessage() {
    final var message = "Hello, this message is for authenticated users";
    return new MessageResponse(message);
  }
}

