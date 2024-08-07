package id.co.develdelsians.jwt.io;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HealthCheckRoute {
    @GetMapping("/_/healthCheck")
    ResponseEntity<Map<String, Object>> healthCheck()
    {
        Map<String, Object> responseMap = new HashMap<>();
        try {
            responseMap.put("app", true);
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        } catch (Exception e) {
            responseMap.put("error", e.getMessage());
            responseMap.put("app", false);
            return ResponseEntity.status(HttpStatus.OK).body(responseMap);
        }
    }
}
