package id.co.develdelsians.jwt.dependencies.impl;

import com.google.gson.Gson;
import id.co.develdelsians.jwt.configs.CommonConfig;
import id.co.develdelsians.jwt.dependencies.IJWTServiceImpl;
import id.co.develdelsians.jwt.exceptions.AppException;
import id.co.develdelsians.jwt.repository.ErrorRepository;
import id.co.develdelsians.jwt.utils.CommonConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

@Slf4j
@Service("jwtService")
@RequiredArgsConstructor
public class JWTServiceImpl implements IJWTServiceImpl {

    private final CommonConfig commonConfig;
    private final ErrorRepository errorConfig;
    
    @Override
    public String create(String type, Map<String, Object> data, int addSeconds) throws Exception {
        if(type.equals(CommonConstant.TOKEN_TAG)) {
            try {
                return createJwt(type, data, addSeconds);
            } catch (Exception e) {
                log.error("Error creating JWT token : {}", e.getMessage());
                String errorCode = errorConfig.getErrorCode("create_token");
                String errorMessage = errorConfig.getErrorMessage("create_token");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
        } else {
            return createJwt(type, data, addSeconds);
        }
    }

    @Override
    public Map<String, Object> validate(String type, String token) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, Exception {
        if(type.equals(CommonConstant.TOKEN_TAG)) {
            try {
                return validateJwt(type,token);
            } catch (Exception e) {
                log.error("Error validate JWT token : {}", e.getMessage());
                String errorCode = errorConfig.getErrorCode("invalid_token");
                String errorMessage = errorConfig.getErrorMessage("invalid_token");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
        } else {
            return validateJwt(type,token);
        }
    }

    @Override
    public String refresh(String type, String token, int addSeconds) throws Exception {
        Map<String, Object> data = validate(type, token);  
        return create(type, data, addSeconds);
    }

    private Date addSecondToDate(int secondsToAdd)
    {
        Date now = new Date();
        log.info("Current date and time: " + now);

        // Get a calendar instance and set the current date and time
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);

        // Add the minutes
        calendar.add(Calendar.SECOND, secondsToAdd);

        // Get the updated date
        Date updatedDate = calendar.getTime();
        log.info("Updated date and time (after adding " + secondsToAdd + " seconds): " + updatedDate);

        return updatedDate;
    }

    private PrivateKey getTokenPrivateKey() throws Exception {
        KeyStore keyStore = getKeystore();
        char[] keyPassword = commonConfig.getKeyPassword().toCharArray();
        Key key = keyStore.getKey(commonConfig.getKeyAlias(), keyPassword);
        if (!(key instanceof PrivateKey)) {
            throw new Exception("Not an instance of a Private Key");
        }
        return (PrivateKey) key;
    }

    private KeyStore getKeystore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] keystorePassword = commonConfig.getJKeyPassword().toCharArray();
        FileInputStream fis = new FileInputStream(commonConfig.getJkey());
        keyStore.load(fis, keystorePassword);
        fis.close();
        return keyStore;
    }

    private PublicKey getTokenPublicKey() throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        KeyStore keyStore = getKeystore();
        Certificate cert = keyStore.getCertificate(commonConfig.getKeyAlias());
        return cert.getPublicKey();
    }


    private PrivateKey getServerSignaturePrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(commonConfig.getKeyServerPrivate()));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey getServerSignaturePublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(commonConfig.getKeyServerPublic()));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    private PrivateKey getClientSignaturePrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(commonConfig.getKeyClientPrivate()));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey getClientSignaturePublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(commonConfig.getKeyClientPublic()));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    @Override
    public String createJwt(String type, Map<String, Object> data, int addSeconds) throws Exception{
        PrivateKey privateKey = switch (type) {
            case CommonConstant.TOKEN_TAG -> getTokenPrivateKey();
            case CommonConstant.SIGNATURE_TAG -> getServerSignaturePrivateKey();
            case CommonConstant.SIGNATURE_CLIENT_TAG -> getClientSignaturePrivateKey();
            default -> throw new IllegalArgumentException("Unexpected value: " + type);
        };
        Gson gson = new Gson();
        log.info("data: " + gson.toJson(data));
        String jws = Jwts.builder()
                .addClaims(data)
                .signWith(privateKey, SignatureAlgorithm.RS512)
                .setExpiration(addSecondToDate(addSeconds))
                .compact();
        log.info("jws: " + jws);
        return jws;
    }

    @Override
    public Map<String, Object> validateJwt(String type, String token) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = switch (type) {
            case CommonConstant.TOKEN_TAG -> getTokenPublicKey();
            case CommonConstant.SIGNATURE_TAG -> getServerSignaturePublicKey();
            case CommonConstant.SIGNATURE_CLIENT_TAG -> getClientSignaturePublicKey();
            default -> throw new IllegalArgumentException("Unexpected value: " + type);
        };
        Claims claims = Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token).getPayload();
        return new HashMap<>(claims);
    }

    @Override
    public int expToInt(Map<String, Object> tokenData) {
        long expLong = ((Number) tokenData.get("exp")).longValue();
        Instant timestampInstant = Instant.ofEpochSecond(expLong);
        Instant now = Instant.now();
        long expInSeconds = ChronoUnit.SECONDS.between(now, timestampInstant);
        return (int) expInSeconds;
    }

    @Override
    public Map<String, String> authHandler(String authorization, Map<String, Object> requestBody) {
        Map<String, String> result = new HashMap<>();
        Gson gson = new Gson();

        int pipeIndex = authorization.indexOf('|');
        //Check Apakah Auth memiliki '|'
        if (pipeIndex!=-1){
            authorization = "Bearer "+ authorization.substring(pipeIndex+1);
        }

        String auth = authorization.substring(7);
        String[] authSplit = auth.split(commonConfig.getDelimeter());
        String token = authSplit[0];
        String session = authSplit[1];
        int lengthToken = token.length();
        int lengthSession = session.length();
        String sampleToken = "....." + token.substring(Math.max(lengthToken - 10, 0));
        String sampleSession = "....." + session.substring(Math.max(lengthSession - 10, 0));
        requestBody.put(CommonConstant.TOKEN_TAG, sampleToken);
        requestBody.put("session", sampleSession);
        result.put("reqString", gson.toJson(requestBody));
        result.put("token", token);
        result.put("session", session);
        return result;
    }

    @Override
    public String encodeBase64(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }
}
