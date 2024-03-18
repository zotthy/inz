package com.work.springsecuritytut.controllers;

import com.work.springsecuritytut.Dtos.LoginDto;
import com.work.springsecuritytut.Dtos.RegisterDto;
import com.work.springsecuritytut.Security.JwtGenerator;
import com.work.springsecuritytut.entity.Role;
import com.work.springsecuritytut.entity.UserEntity;
import com.work.springsecuritytut.repozytory.RoleRepozytory;
import com.work.springsecuritytut.repozytory.UserRepozytory;
import jakarta.persistence.GeneratedValue;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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

    @GetMapping("/hi")
    String hello(){
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

        Optional<Role> role = roleRepozytory.findByName("USER");
        if (role.isPresent()) {
            user.setRoles(Collections.singletonList(role.get()));
        } else {
            return new ResponseEntity<>("Role not found", HttpStatus.NOT_FOUND);
        }
        Role roles = roleRepozytory.findByName("USER").get();
        user.setRoles(Collections.singletonList(roles));

        userRepozytory.save(user);

        return new ResponseEntity<>("register succes", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                loginDto.getUsername(),
                loginDto.getPassword()
        );

        Authentication authenticationResult = authenticationManager.authenticate(token);

        // Pobranie nazwy użytkownika
        String username = authenticationResult.getName();

        // Pobranie uprawnień użytkownika przez mapowanie do listy stringów
        List<String> roles = authenticationResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // Generowanie tokenu JWT
        String jwt = jwtGenerator.generateToknen(username, roles);

        // Zwracam token jako odpowiedź HTTP
        return ResponseEntity.ok(jwt);
    }
}
