package com.binhan.registerapi.service.impl;

import com.binhan.registerapi.exception.UsernameExistedException;
import com.binhan.registerapi.models.RoleEntity;
import com.binhan.registerapi.models.UserEntity;
import com.binhan.registerapi.repository.UserRepository;
import com.binhan.registerapi.security.JwtService;
import com.binhan.registerapi.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;

import static java.nio.file.Files.createTempFile;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public void saveUser(MultipartFile file, String username, String password) throws IOException,
            CertificateException, InvalidNameException {
        if(!docVerify(file)){
            return;
        }
        Optional<UserEntity> userCheckOptional = userRepository.findByUserName(username);
        if(userCheckOptional.isPresent()){
            throw new UsernameExistedException("username already been used");
        }
        /*// Lưu file tạm thời
        Path tempFile = createTempFile("cert", ".p7b");
        Files.write(tempFile, file.getBytes());
        // Đọc thông tin từ file chứng chỉ
        FileInputStream fis = new FileInputStream(tempFile.toFile());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection c = cf.generateCertificates(fis);

        // Lặp qua tất cả các chứng chỉ trong file .p7b
        for (Object item : c) {
            X509Certificate cert = (X509Certificate) item;
            if (isEndUserCertificate(cert)) {
                //get authKeyIdentifier
                String authKeyIdentifier =  getAuthKeyIdentifier(cert);
                //get authInfoAccess
                String authInfoAccess = getAuthInfoAccess(cert);
                //get CRLdistributions
                String distributionCRL = getDistributionCRL(cert);
                //get identifier
                String uid = getUID(cert);

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
                        .build();

                System.out.println(user);
                //userRepository.save(user);
            }
        }*/
        // Lưu file tạm thời
        Path tempFile = createTempFile("cert", ".cer");
        Files.write(tempFile, file.getBytes());

        // Đọc thông tin từ file chứng chỉ
        FileInputStream fis = new FileInputStream(tempFile.toFile());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        // Generate a single certificate
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

        // Check if it's an end-user certificate
        if (isEndUserCertificate(cert)) {
            //get authKeyIdentifier
            String authKeyIdentifier =  getAuthKeyIdentifier(cert);
            //get authInfoAccess
            String authInfoAccess = getAuthInfoAccess(cert);
            //get CRLdistributions
            String distributionCRL = getDistributionCRL(cert);
            //get identifier
            String uid = getUID(cert);
            //get role
            RoleEntity roleEntity = getRole(cert);

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
                    .build();

            System.out.println(user);
            //userRepository.save(user);
        }
    }

    private RoleEntity getRole(X509Certificate cert) throws InvalidNameException {
        String dn = cert.getSubjectDN().getName();
        // Parse the SubjectDN
        LdapName ldapDN = new LdapName(dn);
        // Extract the UID
        String targetAttribute = null;
        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("T")) {
                targetAttribute = rdn.getValue().toString();
                break;
            }
        }
        return null;
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
        byte[] extensionValue = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());

        // Extract the CRLDistributionPoints
        ASN1InputStream asn1In = new ASN1InputStream(extensionValue);
        ASN1OctetString crlDistPointsOctetString = ASN1OctetString.getInstance(asn1In.readObject());
        asn1In.close();

        ASN1InputStream asn1In2 = new ASN1InputStream(crlDistPointsOctetString.getOctets());
        CRLDistPoint crlDistPoints = CRLDistPoint.getInstance(asn1In2.readObject());
        asn1In2.close();
        return String.valueOf(crlDistPoints);
    }


    private String getAuthInfoAccess(X509Certificate cert) throws IOException {
        // Get the AuthorityInformationAccess extension
        byte[] extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        // Extract the AuthorityInformationAccess
        ASN1InputStream asn1In = new ASN1InputStream(extensionValue);
        ASN1Primitive derObject = asn1In.readObject();
        asn1In.close();
        if (derObject instanceof DEROctetString) {
            DEROctetString derOctetString = (DEROctetString) derObject;
            byte[] aiaBytes = derOctetString.getOctets();
            ASN1InputStream aiaIn = new ASN1InputStream(aiaBytes);
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaIn.readObject());
            return String.valueOf(aia);
        }
        return null;
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

    private boolean isEndUserCertificate(X509Certificate cert) {
        return true;
    }

    private boolean docVerify(MultipartFile file) {
        return true;
    }
}
