package com.binhan.registerapi.advice;

import com.binhan.registerapi.exception.UsernameExistedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.security.cert.CertificateException;

@RestControllerAdvice
public class ApplicationExceptionHandler {
    @ExceptionHandler(CertificateException.class)
    public ResponseEntity<String> handleWrongRepeatPasswordException(CertificateException ex){
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    @ExceptionHandler(UsernameExistedException.class)
    public ResponseEntity<String> handleUsernameExistedException(UsernameExistedException ex){
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> Exception(Exception ex){
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }
}
