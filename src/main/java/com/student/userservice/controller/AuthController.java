package com.student.userservice.controller;


import com.student.userservice.model.User;
import com.student.userservice.repo.UserRepository;
import com.student.userservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public Map<String, String> register(@RequestBody User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);

        String token = jwtUtil.generateToken(user.getUsername());
        Map<String, String> response = new HashMap<>();
        response.put("token", token);

        return response;
    }

    @PostMapping("/login")
    public Map<String, String> login(@RequestBody User user) throws AuthenticationException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        String token = jwtUtil.generateToken(user.getUsername());
        Map<String, String> response = new HashMap<>();
        response.put("token", token);

        return response;
    }
}
