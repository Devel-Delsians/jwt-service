package id.co.develdelsians.jwt.io;

import id.co.develdelsians.jwt.dependencies.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/jwt")
@RequiredArgsConstructor
public class JWTRoute {

    private final JWTService jwtService;

    @PostMapping("/create/token")
    ResponseEntity<Map<String, Object>> createToken(@RequestBody Map<String, Object> requestBody){
        return jwtService.createTokenSvc(requestBody);
    }

    @PostMapping("/validate/token")
    ResponseEntity<Map<String, Object>> validateToken(@RequestHeader("Authorization") String authorization, @RequestBody Map<String, Object> requestBody) {
        return  jwtService.validateTokenSvc(authorization, requestBody);
    }

    @PostMapping("/refresh/token")
    ResponseEntity<Map<String, Object>> refreshToken(@RequestHeader("Authorization") String authorization, @RequestBody Map<String, Object> requestBody) {
        return jwtService.refreshTokenSvc(authorization, requestBody);
    }

    @PostMapping("/clear/token")
    ResponseEntity<Map<String, Object>> clearToken(@RequestHeader("Authorization") String authorization, @RequestBody Map<String, Object> requestBody) {
        return jwtService.clearTokenSvc(authorization, requestBody);
    }

    @PostMapping("/signature")
    ResponseEntity<Map<String, Object>> createSignature(@RequestBody Map<String, Object> requestBody) {
        return jwtService.createSignatureSvc(requestBody);
    }

    @GetMapping("/signature")
    ResponseEntity<Map<String, Object>> validateSignature(@RequestHeader("Signature") String signature)
    {
        return jwtService.validateSignatureSvc(signature);
    }

    @PostMapping("/client/signature")
    ResponseEntity<Map<String, Object>> createClientSignature(@RequestBody Map<String, Object> requestBody)
    {
        return jwtService.createClientSignatureSvc(requestBody);
    }

    @GetMapping("/client/signature")
    ResponseEntity<Map<String, Object>> validateClientSignature(@RequestHeader("Signature") String signature)
    {
        return jwtService.validateClientSignatureSvc(signature);
    }
}