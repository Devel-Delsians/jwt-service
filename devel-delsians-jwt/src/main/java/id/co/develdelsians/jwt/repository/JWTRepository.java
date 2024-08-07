package id.co.develdelsians.jwt.repository;

import id.co.develdelsians.jwt.entity.JWT;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface JWTRepository extends JpaRepository<JWT, Integer>{

    // select by email
    @Query(value = "SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END FROM jwt_session WHERE email = ?1", nativeQuery = true)
    int selectByEmail(String email);

    // insert jwt_session
    @Modifying
    @Transactional
    @Query(value = "INSERT INTO jwt_session (email, role, session_id, channel, uuid, created_at, modified_at) VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", nativeQuery = true)
    void insertIntoJwtSession(String email, String role, String session, String channel, String uuid);

    // update token
    @Modifying
    @Transactional
    @Query(value = "UPDATE jwt_session SET session_id = ?1, channel = ?2, uuid = ?3, modified_at = CURRENT_TIMESTAMP WHERE email = ?4", nativeQuery = true)
    void updateTokenByEmail(String session, String channel, String uuid, String email);

    // validate token
    @Query(value = "SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END FROM (SELECT * FROM jwt_session WHERE TRUNC(modified_at) = TRUNC(SYSDATE)) filtered_sessions WHERE email = ?1 AND DBMS_LOB.SUBSTR(session_id, 4000, 1) = ?2", nativeQuery = true)
    int validateToken(String email, String session);

    // Clear token
    @Modifying
    @Transactional
    @Query(value = "UPDATE jwt_session SET session_id = ?1, modified_at = CURRENT_TIMESTAMP WHERE email = ?2", nativeQuery = true)
    void clearTokenByEmail(String session, String email);

}
