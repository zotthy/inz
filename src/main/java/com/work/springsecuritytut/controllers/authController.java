package com.work.springsecuritytut.controllers;

import com.work.springsecuritytut.Dtos.LoginDto;
import com.work.springsecuritytut.Dtos.RegisterDto;
import com.work.springsecuritytut.Security.JwtGenerator;
import com.work.springsecuritytut.entity.Role;
import com.work.springsecuritytut.entity.UserEntity;
import com.work.springsecuritytut.repozytory.RoleRepozytory;
import com.work.springsecuritytut.repozytory.UserRepozytory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
public class authController {

    private final AuthenticationManager authenticationManager;
    private final JwtGenerator jwtGenerator;
    private UserRepozytory userRepozytory;
    private RoleRepozytory roleRepozytory;
    private PasswordEncoder passwordEncoder;

    public authController(AuthenticationManager authenticationManager, UserRepozytory userRepozytory,
                          RoleRepozytory roleRepozytory, PasswordEncoder passwordEncoder, JwtGenerator jwtGenerator) {
        this.authenticationManager = authenticationManager;
        this.userRepozytory = userRepozytory;
        this.roleRepozytory = roleRepozytory;
        this.passwordEncoder = passwordEncoder;
        this.jwtGenerator = jwtGenerator;
    }

    @GetMapping("/h")
    String hh(@RequestHeader("Authorization") String token){
        System.out.println(token);
        return "d";
    }
    @GetMapping("/hi")
    String hello(@RequestHeader("Authorization") String token){
        System.out.println(token);
        return "hello";
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto){

        if (userRepozytory.existsByUsername(registerDto.getUsername())){
            return new ResponseEntity<>("user is taken",HttpStatus.CONFLICT);
        }

        UserEntity user = new UserEntity();

        user.setUsername(registerDto.getUsername());
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        user.setEmail(registerDto.getEmail());

        Optional<Role> role = roleRepozytory.findByName("USER_ROLE");
        if (role.isPresent()) {
            user.setRoles(Collections.singletonList(role.get()));
        } else {
            return new ResponseEntity<>("Role not found", HttpStatus.NOT_FOUND);
        }
        Role roles = roleRepozytory.findByName("USER_ROLE").get();
        user.setRoles(Collections.singletonList(roles));

        userRepozytory.save(user);

        return new ResponseEntity<>("register succes", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDto loginDto) {
        try {
            // Proces autentykacji
            Authentication authentication = authenticationManager.authenticate(new
                    UsernamePasswordAuthenticationToken(loginDto.getEmail(), loginDto.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Pobierz pełne informacje o użytkowniku
            UserEntity user = userRepozytory.findByEmail(loginDto.getEmail())
                    .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + loginDto.getEmail()));

            // Generowanie tokenu
            List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
            String token = jwtGenerator.generateToknen(user.getEmail(), roles);

            // Zwróć token jako odpowiedź
            return ResponseEntity.ok().body(token);

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

    }
}
