package com.binhan.registerapi.service;

import com.binhan.registerapi.dto.request.AuthenticationRequest;
import com.binhan.registerapi.dto.response.AuthenticationResponse;
import org.springframework.web.multipart.MultipartFile;

import javax.naming.InvalidNameException;
import java.io.IOException;
import java.security.cert.CertificateException;

public interface AuthenticationService {
    AuthenticationResponse saveUser(MultipartFile file, String username, String password) throws IOException, CertificateException, InvalidNameException;

    AuthenticationResponse authenticate(AuthenticationRequest request);
}
