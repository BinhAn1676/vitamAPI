package com.binhan.registerapi.controllers;

import com.binhan.registerapi.service.TestService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/test")
public class TestController {

    private final TestService testService;

    @GetMapping("/encrypt")
    public ResponseEntity<?> encryptData(@RequestParam("data") String data) throws Exception {
        String encryptData = testService.encryptData(data);
        return ResponseEntity.ok(encryptData);
    }


}
