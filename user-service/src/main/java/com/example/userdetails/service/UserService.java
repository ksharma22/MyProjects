package com.example.userdetails.service;

import com.example.userdetails.model.User;
import com.example.userdetails.repository.UserRepository;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository repository;
    private final BasicParserPool parserPool;
    private final X509Credential validationCredential;

    public UserService(UserRepository repository,
                       @Value("${saml.trusted-certificate:}") String trustedCertificatePem) {
        this.repository = repository;
        this.parserPool = new BasicParserPool();
        this.parserPool.setNamespaceAware(true);
        try {
            this.parserPool.initialize();
        } catch (XMLParserException e) {
            throw new SamlValidationException("Unable to initialize parser pool", e);
        }

        initializeOpenSaml();
        this.validationCredential = buildCredential(trustedCertificatePem);
    }

    public List<User> getAllUsers() {
        return repository.findAll();
    }

    public Optional<User> getUserById(Long id) {
        return repository.findById(id);
    }

    public Optional<User> getUserByUsername(String username) {
        return repository.findByUsername(username);
    }

    public Optional<User> getAuthorizedUserById(String samlResponseBase64, Long id) {
        Assertion assertion = parseAssertion(samlResponseBase64);
        validateAssertion(assertion);
        String subjectName = extractSubject(assertion);
        return repository.findById(id).filter(user -> subjectName.equals(user.getUsername()));
    }

    private void initializeOpenSaml() {
        try {
            InitializationService.initialize();
            new JavaCryptoValidationInitializer().init();
        } catch (InitializationException e) {
            throw new SamlValidationException("Failed to initialize OpenSAML", e);
        }
    }

    private Assertion parseAssertion(String samlResponseBase64) {
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(samlResponseBase64))) {
            Document document = parserPool.parse(inputStream);
            Element root = document.getDocumentElement();
            XMLObject xmlObject = XMLObjectSupport.unmarshallFromElement(root);
            if (!(xmlObject instanceof Response)) {
                throw new SamlValidationException("SAML payload is not a Response");
            }
            Response response = (Response) xmlObject;
            if (response.getAssertions().isEmpty()) {
                throw new SamlValidationException("SAML response contains no assertions");
            }
            return response.getAssertions().get(0);
        } catch (IOException | SAXException | UnmarshallingException e) {
            throw new SamlValidationException("Failed to parse SAML response", e);
        }
    }

    private void validateAssertion(Assertion assertion) {
        validateSignature(assertion);
        validateConditions(assertion);
    }

    private void validateSignature(Assertion assertion) {
        Signature signature = assertion.getSignature();
        if (signature == null) {
            throw new SamlValidationException("SAML assertion is not signed");
        }
        try {
            SignatureValidator.validate(signature, validationCredential);
        } catch (SignatureException e) {
            throw new SamlValidationException("SAML signature validation failed", e);
        }
    }

    private void validateConditions(Assertion assertion) {
        Conditions conditions = assertion.getConditions();
        if (conditions == null) {
            return;
        }
        Instant now = Instant.now();
        if (conditions.getNotBefore() != null && now.isBefore(conditions.getNotBefore().toInstant())) {
            throw new SamlValidationException("SAML assertion is not yet valid");
        }
        if (conditions.getNotOnOrAfter() != null && !now.isBefore(conditions.getNotOnOrAfter().toInstant())) {
            throw new SamlValidationException("SAML assertion has expired");
        }
    }

    private String extractSubject(Assertion assertion) {
        Subject subject = assertion.getSubject();
        if (subject == null || subject.getNameID() == null || subject.getNameID().getValue() == null) {
            throw new SamlValidationException("SAML assertion subject is missing");
        }
        return subject.getNameID().getValue();
    }

    private X509Credential buildCredential(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new SamlValidationException("Trusted SAML certificate is not configured");
        }
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            byte[] decoded = Base64.getDecoder().decode(cleanPem(pem));
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(decoded));
            return new BasicX509Credential(certificate);
        } catch (CertificateException e) {
            throw new SamlValidationException("Failed to build validation credential from trusted certificate", e);
        }
    }

    private String cleanPem(String pem) {
        return pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
    }
}
