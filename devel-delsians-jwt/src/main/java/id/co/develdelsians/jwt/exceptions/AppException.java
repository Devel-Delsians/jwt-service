package id.co.develdelsians.jwt.exceptions;

import org.springframework.http.HttpStatusCode;

public class AppException extends Exception{
    private final String code;

    private final HttpStatusCode httpStatusCode;
    private final String message;

    public AppException(String code, String message, HttpStatusCode httpStatusCode){
        this.code = code;
        this.message = message;
        this.httpStatusCode = httpStatusCode;
    }

    public String getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public HttpStatusCode getHttpStatusCode() {
        return httpStatusCode;
    }
}
