package id.co.develdelsians.jwt.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import id.co.develdelsians.jwt.repository.ErrorRepository;

@Configuration
public class ErrorConfig {

    @Bean
    public ErrorRepository errorRepository() {
        return new ErrorRepository();
    }
}
