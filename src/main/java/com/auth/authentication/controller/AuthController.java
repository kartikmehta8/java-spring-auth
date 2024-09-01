package com.auth.authentication.controller;

import com.auth.authentication.model.User;
import com.auth.authentication.service.UserService;
import com.auth.authentication.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  @Autowired
  private UserService userService;

  @Autowired
  private JwtUtil jwtUtil;

  @Autowired
  private AuthenticationManager authenticationManager;

  @PostMapping("/register")
  public ResponseEntity<?> register(@RequestBody User user) {
    User newUser = userService.registerUser(user.getEmail(), user.getPassword());
    return ResponseEntity.ok(newUser);
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody User user) {
    @SuppressWarnings("unused")
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));

    String jwt = jwtUtil.generateToken(user.getEmail());
    return ResponseEntity.ok(jwt);
  }
}
