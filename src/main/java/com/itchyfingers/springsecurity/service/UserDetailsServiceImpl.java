package com.itchyfingers.springsecurity.service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@AllArgsConstructor(onConstructor_ = {@Autowired})
public class UserDetailsServiceImpl implements UserDetailsService {

  private final PasswordEncoder passwordEncoder;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    log.info("loadUserByUsername -  username:{}", username);

    final var user = getUserDetails(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    return user;
  }

  private Optional<UserDetails> getUserDetails(String username) {
    final var validUsers = List.of("userone", "usertwo", "userthree");
    if (validUsers.contains(username)) {
      final var userDetails = User.withUsername(username)
          .password(passwordEncoder.encode("password"))
          .roles("USER")
          //.authorities(List.of(new SimpleGrantedAuthority("ROLE_USER")))
          .build();
      return Optional.of(userDetails);
    }
    return Optional.empty();
  }

}
