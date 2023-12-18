package com.binhan.registerapi.service.impl;

import com.binhan.registerapi.security.JwtService;
import com.binhan.registerapi.service.TestService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
@RequiredArgsConstructor
public class TestServiceImpl implements TestService {

    private final JwtService jwtService;

    @Override
    public String encryptData(String data) throws Exception {
        try{
            SecretKey secretKey = jwtService.generateAESKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return new String(encrypted);
        }catch(Exception e){
            throw new Exception("error");
        }
    }

    //tạo JWS
    /*public static void main(String[] args) throws Exception {
        String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";
        KeyPair keyPair = generateRSAKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        RsaSigner signer = new RsaSigner(privateKey.getEncoded());
        String jws = JwtHelper.encode(payload, signer).getEncoded();
        System.out.println(jws);
    }*/
}
