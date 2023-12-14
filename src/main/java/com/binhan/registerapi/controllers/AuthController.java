package com.binhan.registerapi.controllers;

import com.binhan.registerapi.dto.request.AuthenticationRequest;
import com.binhan.registerapi.service.AuthenticationService;
import com.binhan.registerapi.service.impl.AuthenticationServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.naming.InvalidNameException;
import java.io.IOException;
import java.security.cert.CertificateException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestParam("cert") MultipartFile file,
                                      @RequestParam("username") String username,
                                      @RequestParam("password") String password) throws CertificateException, IOException, InvalidNameException {
        if(file == null){
            return ResponseEntity.status(400).body("cant find certificate file");
        }
        return ResponseEntity.ok(authenticationService.saveUser(file,username,password));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
