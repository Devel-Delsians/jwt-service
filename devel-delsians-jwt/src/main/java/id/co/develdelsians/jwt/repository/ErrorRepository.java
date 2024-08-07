package id.co.develdelsians.jwt.repository;

import java.util.HashMap;
import java.util.Map;

import id.co.develdelsians.jwt.configs.ErrorDetail;
import lombok.Getter;

@Getter
public class ErrorRepository {

    private final Map<String, ErrorDetail> paramError;

    public ErrorRepository() {
        paramError = new HashMap<>();
        paramError.put("bad_request", new ErrorDetail("9001", "BAD REQUEST"));
        paramError.put("create_token", new ErrorDetail("9002", "FAILED TO CREATE TOKEN"));
        paramError.put("invalid_token", new ErrorDetail("9003", "INVALID TOKEN"));
        paramError.put("validate_token", new ErrorDetail("9004", "FAILED TO VALIDATE TOKEN"));
        paramError.put("invalid_email", new ErrorDetail("9005", "INVALID EMAIL"));
        paramError.put("internal_exception", new ErrorDetail("9099", "INTERNAL SERVER ERROR"));
    }
    
    public String getErrorCode(String key) {
        ErrorDetail errorDetail = paramError.get(key);
        return (errorDetail != null) ? errorDetail.getCode() : "0000";
    }

    public String getErrorMessage(String key) {
        ErrorDetail errorDetail = paramError.get(key);
        return (errorDetail != null) ? errorDetail.getMessage() : "Unknown error";
    }
}
