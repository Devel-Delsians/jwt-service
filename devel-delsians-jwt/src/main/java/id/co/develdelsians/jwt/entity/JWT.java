package id.co.develdelsians.jwt.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "jwt_session")
@Getter
@Setter
public class JWT {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int Id;

    @Column(name = "email")
    private String email;

    @Column(name = "role")
    private String role;
    
    @Lob
    @Column(name = "session_id", columnDefinition = "CLOB")
    private String session;
    
    @Column(name = "channel")
    private String channel;

    @Column(name = "uuid")
    private String uuid;
    
    @Column(name = "created_at")
    private LocalDateTime createdAt;
    
    @Column(name = "modified_at")
    private LocalDateTime modifiedAt;
    
}
