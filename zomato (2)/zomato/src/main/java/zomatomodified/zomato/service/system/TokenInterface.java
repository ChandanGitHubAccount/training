package zomatomodified.zomato.service.system;

import org.springframework.jdbc.core.BeanPropertyRowMapper;
import zomatomodified.zomato.model.Tokens;

import java.time.LocalDateTime;
import java.util.List;

public interface TokenInterface {
    boolean verifyToken(String token);
    String generate();

    void remove(String secureToken,String username);

    void save(String token, String username, LocalDateTime now, LocalDateTime plusMinutes, String toString);

    List<Tokens> getTokenDetail(String token);

}
