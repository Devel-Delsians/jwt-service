package id.co.develdelsians.jwt.dependencies;

import com.google.gson.Gson;
import id.co.develdelsians.jwt.configs.CommonConfig;
import id.co.develdelsians.jwt.dependencies.impl.JWTServiceImpl;
import id.co.develdelsians.jwt.exceptions.AppException;
import id.co.develdelsians.jwt.repository.ErrorRepository;
import id.co.develdelsians.jwt.repository.JWTRepository;
import id.co.develdelsians.jwt.utils.CommonConstant;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Service
@Slf4j
@RequiredArgsConstructor
public class JWTService {

    private final JWTServiceImpl jwtService;
    private final CommonConfig commonConfig;
    private final JWTRepository jwtRepository;
    private final ErrorRepository errorConfig;

    public ResponseEntity<Map<String, Object>> createTokenSvc (Map<String, Object> requestBody) {
        String refnum = "{refnum}";
        String errorCode;
        String errorMessage;
        Map<String, Object> responseMap = new HashMap<>();
        Gson gson = new Gson();
        try {
            Set<String> requiredFields = Set.of("refnum", "email", "username", "channel", "role", "uuid", "authorities");
            // Check for missing fields
            for (String field : requiredFields) {
                if (!requestBody.containsKey(field)) {
                    log.error("{} - Field " + field + " is missing", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            refnum = (String) requestBody.get("refnum");
            responseMap.put("refnum", refnum);
            // Check for extra fields
            for (String key : requestBody.keySet()) {
                if (!requiredFields.contains(key)) {
                    log.error("{} - Field " + key + " is not allowed", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            String reqString = gson.toJson(requestBody);
            log.info("{} - start to processing create token. request:\n{}", refnum, reqString);
            // get request
            String email = (String) requestBody.get("email");
            String role = (String) requestBody.get("role");
            String channel = (String) requestBody.get("channel");
            String uuid = (String) requestBody.get("uuid");
            String session = email + uuid + refnum;
            String sessionBase64 = jwtService.encodeBase64(session);
            requestBody.remove("refnum");
            // create token
            String token = jwtService.create(CommonConstant.TOKEN_TAG, requestBody, commonConfig.getExpiredAt());
            String tokenRes = token + commonConfig.getDelimeter() + sessionBase64;
            // check email is exist
            int isExist = jwtRepository.selectByEmail(email);
            if (isExist != 0) {
                jwtRepository.updateTokenByEmail(sessionBase64, channel, uuid, email);
            } else {
                jwtRepository.insertIntoJwtSession(email, role, sessionBase64, channel, uuid);
            }
            // mapping response
            responseMap.put("token", tokenRes);
            responseMap.put("expiredTime", commonConfig.getExpiredAt());
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        } catch (AppException e) {
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        } catch (Exception e) {
            log.error("{} - An unexpected error occurred. {}", refnum, e.getMessage());
            responseMap.put(CommonConstant.CODE_TAG, errorConfig.getErrorCode("internal_exception"));
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, errorConfig.getErrorMessage("internal_exception"));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        } finally {
            String resString = gson.toJson(responseMap);
            log.info("{} - End-to-End processing create token. response:\n{}", refnum, resString);
        }
    }

    public ResponseEntity<Map<String, Object>> validateTokenSvc(String authorization, Map<String, Object> requestBody) {
        String refnum = "{refnum}";
        String errorCode;
        String errorMessage;
        Map<String, String> splitReq;
        Map<String, Object> responseMap = new HashMap<>();
        Map<String, Object> tokenData = new HashMap<>();
        Gson gson = new Gson();
        try {
            Set<String> requiredFields = Set.of("refnum", "email");
            // Check for missing fields
            for (String field : requiredFields) {
                if (!requestBody.containsKey(field)) {
                    log.error("{} - Field " + field + " is missing", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            refnum = (String) requestBody.get("refnum");
            responseMap.put("refnum", refnum);
            // Check for extra fields
            for (String key : requestBody.keySet()) {
                if (!requiredFields.contains(key)) {
                    log.error("{} - Field " + key + " is not allowed", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            // validate auth
            if (authorization == null) {
                log.error("{} - You are not authorized", refnum);
                errorCode = errorConfig.getErrorCode("bad_request");
                errorMessage = errorConfig.getErrorMessage("bad_request");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            if (!authorization.startsWith("Bearer")) {
                log.error("{} - You have to set Bearer <token>", refnum);
                errorCode = errorConfig.getErrorCode("bad_request");
                errorMessage = errorConfig.getErrorMessage("bad_request");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            splitReq = jwtService.authHandler(authorization, requestBody);
            String reqString = splitReq.get("reqString");
            String token = splitReq.get("token");
            String session = splitReq.get("session");
            log.info("{} - start to processing validate token. request:\n{}", refnum, reqString);
            // get request
            String email = (String) requestBody.get("email");
            // validate token, session
            tokenData = jwtService.validate(CommonConstant.TOKEN_TAG, token);
            int isValid = jwtRepository.validateToken(email, session);
            if (isValid == 0) {
                log.error("{} - The provided token does not exist in the database", refnum);
                errorCode = errorConfig.getErrorCode("validate_token");
                errorMessage = errorConfig.getErrorMessage("validate_token");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            // mapping exp to second
            int expInSeconds = jwtService.expToInt(tokenData);
            // mapping response
            tokenData.put("exp", expInSeconds);
            tokenData.put("refnum", refnum);
            return ResponseEntity.status(HttpStatus.OK).body(tokenData);
        } catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        } catch (Exception e) {
            log.error("{} - An unexpected error occurred. {}", refnum, e.getMessage());
            responseMap.put(CommonConstant.CODE_TAG, errorConfig.getErrorCode("internal_exception"));
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, errorConfig.getErrorMessage("internal_exception"));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        } finally {
            if (!responseMap.containsKey(CommonConstant.CODE_TAG)) {
                String resString = gson.toJson(tokenData);
                log.info("{} - End-to-End processing validate token. response:\n{}", refnum, resString);
            } else {
                String resString = gson.toJson(responseMap);
                log.info("{} - End-to-End processing validate token. response:\n{}", refnum, resString);
            }
        }
    }

    public ResponseEntity<Map<String, Object>> refreshTokenSvc(String authorization, Map<String, Object> requestBody) {
        String refnum = "{refnum}";
        String errorCode;
        String errorMessage;
        Map<String, String> splitReq;
        Map<String, Object> responseMap = new HashMap<>();
        Gson gson = new Gson();
        try {
            //validate request
            Set<String> requiredFields = Set.of("refnum","email", "channel", "uuid", "expired");
            // Check for missing fields
            for (String field : requiredFields) {
                if (!requestBody.containsKey(field)) {
                    log.error("{} - Field " + field + " is missing", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            refnum = (String) requestBody.get("refnum");
            responseMap.put("refnum", refnum);
            // Check for extra fields
            for (String key : requestBody.keySet()) {
                if (!requiredFields.contains(key)) {
                    log.error("{} - Field " + key + " is not allowed", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            // validate auth
            if (authorization == null) {
                log.error("{} - You are not authorized", refnum);
                errorCode = errorConfig.getErrorCode("bad_request");
                errorMessage = errorConfig.getErrorMessage("bad_request");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            if (!authorization.startsWith("Bearer")) {
                log.error("{} - You have to set Bearer <token>", refnum);
                errorCode = errorConfig.getErrorCode("bad_request");
                errorMessage = errorConfig.getErrorMessage("bad_request");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            splitReq = jwtService.authHandler(authorization, requestBody);
            String reqString = splitReq.get("reqString");
            String token = splitReq.get("token");
            String session = splitReq.get("session");
            log.info("{} - start to processing refresh token. request:\n{}", refnum, reqString);
            //get request
            String email = (String) requestBody.get("email");
            String channel = (String) requestBody.get("channel");
            String expiredString = (String) requestBody.get("expired");
            int expired = Integer.parseInt(expiredString);
            //refresh token
            String newToken = jwtService.refresh(CommonConstant.TOKEN_TAG, token, expired);
            String tokenRes = newToken + commonConfig.getDelimeter() + session;
            //get response & throw to response
            responseMap.put("token", tokenRes);
            responseMap.put("email", email);
            responseMap.put("channel", channel);
            responseMap.put("expiredTime", expired);
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        }
        catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        }
        catch (Exception e) {
            log.error("{} - An unexpected error occurred. {}", refnum, e.getMessage());
            responseMap.put(CommonConstant.CODE_TAG, CommonConstant.TAG_500);
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }finally {
            String resString = gson.toJson(responseMap);
            log.info("{} - End-to-End processing refresh token. response:\n{}", refnum, resString);
        }
    }

    public ResponseEntity<Map<String, Object>> clearTokenSvc(String authorization, Map<String, Object> requestBody) {
        String refnum = "{refnum}";
        String errorCode;
        String errorMessage;
        Map<String, String> splitReq;
        Map<String, Object> responseMap = new HashMap<>();
        Gson gson = new Gson();
        try {
            //validate request
            Set<String> requiredFields = Set.of("refnum", "email");
            // Check for missing fields
            for (String field : requiredFields) {
                if (!requestBody.containsKey(field)) {
                    log.error("{} - Field " + field + " is missing", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            refnum = (String) requestBody.get("refnum");
            responseMap.put("refnum", refnum);
            // Check for extra fields
            for (String key : requestBody.keySet()) {
                if (!requiredFields.contains(key)) {
                    log.error("{} - Field " + key + " is not allowed", refnum);
                    errorCode = errorConfig.getErrorCode("bad_request");
                    errorMessage = errorConfig.getErrorMessage("bad_request");
                    throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
                }
            }
            // validate auth
            if (authorization == null) {
                log.error("{} - You are not authorized", refnum);
                errorCode = errorConfig.getErrorCode("bad_request");
                errorMessage = errorConfig.getErrorMessage("bad_request");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            if (!authorization.startsWith("Bearer")) {
                log.error("{} - You have to set Bearer <token>", refnum);
                errorCode = errorConfig.getErrorCode("bad_request");
                errorMessage = errorConfig.getErrorMessage("bad_request");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            splitReq = jwtService.authHandler(authorization, requestBody);
            String reqString = splitReq.get("reqString");
            String token = splitReq.get("token");
            log.info("{} - start to processing clear token. request:\n{}", refnum, reqString);
            //get request & clear token
            String email = (String) requestBody.get("email");
            String session = "";
            String tokenRes = token + commonConfig.getDelimeter();
            // Check if username exists
            int isExist = jwtRepository.selectByEmail(email);
            if (isExist != 0) {
                //update (clear) token when username exist
                jwtRepository.clearTokenByEmail(session, email);
            } else {
                // Handle the case when email does not exist
                errorCode = errorConfig.getErrorCode("invalid_email");
                errorMessage = errorConfig.getErrorMessage("invalid_email");
                throw new AppException(errorCode, errorMessage, HttpStatus.BAD_REQUEST);
            }
            //get response & throw to response
            responseMap.put("username", email);
            responseMap.put("token", tokenRes);
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        }
        catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        }
        catch (Exception e) {
            log.error("{} - An unexpected error occurred. {}", refnum, e.getMessage());
            responseMap.put(CommonConstant.CODE_TAG, CommonConstant.TAG_500);
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }finally {
            String resString = gson.toJson(responseMap);
            log.info("{} - End-to-End processing clear token. response:\n{}", refnum, resString);
        }

    }

    public ResponseEntity<Map<String, Object>> createSignatureSvc(Map<String, Object> requestBody) {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            String token = jwtService.create(CommonConstant.SIGNATURE_TAG, requestBody, commonConfig.getExpiredAt());
            responseMap.put("token", token);
            responseMap.put("expiredTime", commonConfig.getExpiredAt());
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        }
        catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        }
        catch (Exception e) {
            responseMap.put(CommonConstant.CODE_TAG, CommonConstant.TAG_500);
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }
    }

    public ResponseEntity<Map<String, Object>> validateSignatureSvc(String signature) {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            if (signature == null) throw new AppException("400","you are not authorized", HttpStatus.BAD_REQUEST);
            return ResponseEntity.status(HttpStatus.OK).body(jwtService.validate(CommonConstant.SIGNATURE_TAG, signature));
        }
        catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        }
        catch (Exception e) {
            responseMap.put(CommonConstant.CODE_TAG, CommonConstant.TAG_500);
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
        }
    }

    public ResponseEntity<Map<String, Object>> createClientSignatureSvc(Map<String, Object> requestBody) {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            String token = jwtService.create(CommonConstant.SIGNATURE_CLIENT_TAG, requestBody, commonConfig.getExpiredAt());
            responseMap.put("token", token);
            responseMap.put("expiredTime", commonConfig.getExpiredAt());
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        }
        catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        }
        catch (Exception e) {
            responseMap.put(CommonConstant.CODE_TAG, CommonConstant.TAG_500);
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseMap);
        }
    }

    public ResponseEntity<Map<String, Object>> validateClientSignatureSvc(String signature) {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            if (signature == null) throw new AppException("400","you are not authorized", HttpStatus.BAD_REQUEST);
            return ResponseEntity.status(HttpStatus.OK).body(jwtService.validate(CommonConstant.SIGNATURE_CLIENT_TAG, signature));
        }
        catch (AppException e){
            responseMap.put(CommonConstant.CODE_TAG, e.getCode());
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(e.getHttpStatusCode()).body(responseMap);
        }
        catch (Exception e) {
            responseMap.put(CommonConstant.CODE_TAG, CommonConstant.TAG_500);
            responseMap.put(CommonConstant.ERROR_MESSAGE_TAG, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseMap);
        }
    }
}
