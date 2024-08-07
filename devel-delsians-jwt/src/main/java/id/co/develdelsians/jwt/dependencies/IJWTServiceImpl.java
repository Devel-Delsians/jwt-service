package id.co.develdelsians.jwt.dependencies;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public interface IJWTServiceImpl {
    public String create(String type, Map<String, Object> data, int addSeconds) throws Exception;
    public Map<String, Object> validate(String type, String token) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception;
    public String createJwt(String type, Map<String, Object> data, int addSeconds) throws Exception;
    public Map<String, Object> validateJwt(String type, String token) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException;
    public String refresh(String type, String token, int expired) throws Exception;
    public int expToInt(Map<String, Object> tokenData);
    public Map<String, String> authHandler(String authorization, Map<String, Object> requestBody);
    public String encodeBase64(String input);
}
