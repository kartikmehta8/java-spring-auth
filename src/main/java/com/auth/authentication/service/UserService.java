package com.auth.authentication.service;

import com.auth.authentication.model.User;
import com.auth.authentication.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class UserService implements UserDetailsService {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
    this.userRepository = userRepository;
    this.bCryptPasswordEncoder = bCryptPasswordEncoder;
  }

  public User registerUser(String email, String password) {
    if (userRepository.findByEmail(email).isPresent()) {
      throw new RuntimeException("User already exists!");
    }
    String encodedPassword = bCryptPasswordEncoder.encode(password);
    User user = new User();
    user.setEmail(email);
    user.setPassword(encodedPassword);
    return userRepository.save(user);
  }

  public User authenticateUser(String email, String password) {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new RuntimeException("User not found!"));
    if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
      throw new RuntimeException("Invalid credentials!");
    }
    return user;
  }

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

    return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(),
        Collections.emptyList());
  }
}
