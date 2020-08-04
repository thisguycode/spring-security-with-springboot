package com.itchyfingers.springsecurity.config;

import com.itchyfingers.springsecurity.filter.JwtVerificationFilter;
import com.itchyfingers.springsecurity.filter.LoginFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private UserDetailsService userDetailsService;

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtVerificationFilter jwtAuthFilter() {
    return new JwtVerificationFilter();
  }

  @Bean
  public LoginFilter loginFilter() throws Exception {
    final var loginFilter = new LoginFilter();
    loginFilter.setFilterProcessesUrl("/auth/login");
    loginFilter.setAuthenticationManager(authenticationManagerBean());
    return loginFilter;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/messages/public/**").hasAuthority("ROLE_USER")
        .antMatchers("/messages/private/**").hasAuthority("ROLE_ADMIN")
        .anyRequest().authenticated();

    http.addFilterBefore(jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);
    http.addFilter(loginFilter());
  }
}
