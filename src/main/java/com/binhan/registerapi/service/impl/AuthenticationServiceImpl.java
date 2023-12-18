package com.binhan.registerapi.service.impl;

import com.binhan.registerapi.dto.request.AuthenticationRequest;
import com.binhan.registerapi.dto.response.AuthenticationResponse;
import com.binhan.registerapi.exception.UsernameExistedException;
import com.binhan.registerapi.models.RoleEntity;
import com.binhan.registerapi.models.UserEntity;
import com.binhan.registerapi.repository.RoleRepository;
import com.binhan.registerapi.repository.UserRepository;
import com.binhan.registerapi.security.JwtService;
import com.binhan.registerapi.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.json.JSONObject;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

import static java.nio.file.Files.createTempFile;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse saveUser(MultipartFile file, String username, String password) throws IOException,
            CertificateException, InvalidNameException {
        UserEntity savedUser;
        String jwtToken = null;
        if (file == null) {
            return null;
        }
        Optional<UserEntity> userCheckOptional = userRepository.findByUserName(username);
        if (userCheckOptional.isPresent()) {
            throw new UsernameExistedException("username already been used");
        }
        Path tempFile = createTempFile("cert", ".cer");
        Files.write(tempFile, file.getBytes());
        FileInputStream fis = new FileInputStream(tempFile.toFile());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        // goi api docVerify
        try {
            boolean check = docVerify(cert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        String authKeyIdentifier = getAuthKeyIdentifier(cert);
        String authInfoAccess = getAuthInfoAccess(cert);
        String distributionCRL = getDistributionCRL(cert);
        //get identifier
        String uid = getUID(cert);
        RoleEntity role = getRole(cert);
        Set<RoleEntity> roleEntities = new HashSet<>();
        roleEntities.add(role);

        UserEntity user = UserEntity.builder()
                .serialNumber(String.valueOf(cert.getSerialNumber()))
                .issuer(String.valueOf(cert.getIssuerDN()))
                .validFrom(String.valueOf(cert.getNotBefore()))
                .validTo(String.valueOf(cert.getNotAfter()))
                .subject(String.valueOf(cert.getSubjectDN()))
                .authKeyIdentifier(String.valueOf(authKeyIdentifier))
                .authInfoAccess(authInfoAccess)
                .basicConstraints(String.valueOf(cert.getBasicConstraints()))
                .distributionCRL(distributionCRL)
                .keyUsage(Arrays.toString(cert.getKeyUsage()))
                .userName(username)
                .password(passwordEncoder.encode(password))
                .identify(uid)
                .roles(roleEntities)
                .build();
        savedUser = userRepository.save(user);
        jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByUserName(request.getUsername())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    private RoleEntity getRole(X509Certificate cert) throws InvalidNameException {
        String dn = cert.getSubjectDN().getName();
        String temp;
        LdapName ldapDN = new LdapName(dn);
        Optional<RoleEntity> role = null;
        String targetAttribute = null;
        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("T")) {
                targetAttribute = rdn.getValue().toString();
                role = roleRepository.findByName(targetAttribute);
                if (role.isPresent()) {
                    break;
                }
            }
        }
        return role.get();
    }

    private String getUID(X509Certificate cert) throws InvalidNameException {
        String dn = cert.getSubjectDN().getName();
        // Parse the SubjectDN
        LdapName ldapDN = new LdapName(dn);
        // Extract the UID
        String uid = null;
        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("UID")) {
                uid = rdn.getValue().toString();
                return uid;
            }
        }
        return uid;
    }

    private String getDistributionCRL(X509Certificate cert) throws IOException {
        String url = null;
        byte[] crlPointExtValue = cert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        CRLDistPoint distPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(crlPointExtValue));
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralNames generalNames = GeneralNames.getInstance(dpn.getName());
                for (GeneralName generalName : generalNames.getNames()) {
                    if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        url = generalName.getName().toString();
                    }
                }
            }
        }
        return url;
    }


    private String getAuthInfoAccess(X509Certificate cert) throws IOException {
        String url = null;
        byte[] aiaExtValue = cert.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(aiaExtValue));
        for (AccessDescription ad : aia.getAccessDescriptions()) {
            if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                if (ad.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier) {
                    url = ad.getAccessLocation().getName().toString();
                }
            }
        }
        return url;
    }

    private String getAuthKeyIdentifier(X509Certificate cert) {
        // Get the AuthorityKeyIdentifier extension
        byte[] extensionValue = cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        // Extract the AuthorityKeyIdentifier
        ASN1OctetString akiOctetString = ASN1OctetString.getInstance(extensionValue);
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiOctetString.getOctets());
        int keyIdIndex = String.valueOf(aki).indexOf("KeyID");
        String keyIdSubstring = String.valueOf(aki).substring(keyIdIndex);
        return keyIdSubstring;

    }

    public boolean docVerify(X509Certificate cert) throws Exception {
        //call docVerify
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.add("Sec-Fetch-Site", "cross-site");
        headers.add("Sec-Fetch-Mode", "cors");
        headers.add("Sec-Fetch-Dest", "empty");
        headers.add("Referer", "http://localhost:4300/");
        headers.add("Accept-Language", "vi");
        headers.add("Cookie", "JSESSIONID=993304C6BF723DBB4CA79681352F0820; JSESSIONID=81E2FC45B1AEB05AE933CFD6CB901E96");
        headers.add("Authorization", "Basic YWRtaW46YWRtaW4=");
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("certificate", getCertFileResource(cert));
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.exchange(
                "https://savis-digital.savis.vn/verification-service/verification/api/certificate/file",
                HttpMethod.POST,
                requestEntity,
                String.class
        );
        //tạo map các field đúng
        Map<String, String> correctValues = new HashMap<>();
        correctValues.put("issuerTrust", "TRUSTED");
        correctValues.put("checkValidCurrentTime", "VALID");
        correctValues.put("checkRevokeCurrentTime", "GOOD");
        correctValues.put("checkAlgorithm", "SAFE");
        correctValues.put("checkScope", "VALID");
        // lấy data json từ response
        String verifyJson = response.getBody();
        JSONObject jsonObject = new JSONObject(verifyJson);
        JSONObject data = jsonObject.getJSONObject("data");
        JSONObject certificateResult = data.getJSONObject("certificateResult");
        //kiểm tra field có sai không
        for (String field : correctValues.keySet()) {
            String value = certificateResult.getString(field);
            if (!value.equals(correctValues.get(field))) {
                throw new CertificateException("Invalid value for field '" + field + "': " + value);
            }
        }
        return true;
    }

    private static FileSystemResource getCertFileResource(X509Certificate cert) throws Exception {
        File tempFile = File.createTempFile("cert", ".cer");
        try (FileOutputStream os = new FileOutputStream(tempFile)) {
            os.write(cert.getEncoded());
        }
        return new FileSystemResource(tempFile);
    }
}
