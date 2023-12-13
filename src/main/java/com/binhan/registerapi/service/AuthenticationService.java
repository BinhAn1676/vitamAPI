package com.binhan.registerapi.service;

import org.springframework.web.multipart.MultipartFile;

import javax.naming.InvalidNameException;
import java.io.IOException;
import java.security.cert.CertificateException;

public interface AuthenticationService {
    void saveUser(MultipartFile file, String username, String password) throws IOException, CertificateException, InvalidNameException;
}
