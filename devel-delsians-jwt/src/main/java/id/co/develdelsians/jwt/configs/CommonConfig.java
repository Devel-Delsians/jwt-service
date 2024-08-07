package id.co.develdelsians.jwt.configs;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Data
public class CommonConfig {

    @Value("${app.keys.jkey}")
    String jkey;

    @Value("${app.keys.jkey.keystore-password}")
    String jKeyPassword;

    @Value("${app.keys.jkey.alias}")
    String keyAlias;

    @Value("${app.keys.server.private}")
    String keyServerPrivate;

    @Value("${app.keys.server.public}")
    String keyServerPublic;

    @Value("${app.keys.client.private}")
    String keyClientPrivate;

    @Value("${app.keys.jkey.key-password}")
    String keyPassword;

    @Value("${app.keys.client.public}")
    String keyClientPublic;

    @Value("${app.jwt.expired}")
    int expiredAt;

    @Value("${app.token.delimeter}")
    String delimeter;

}
