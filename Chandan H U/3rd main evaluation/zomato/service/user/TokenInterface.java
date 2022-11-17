package zomato.service.user;

import zomato.model.Tokens;

import java.time.LocalDateTime;
import java.util.List;

public interface TokenInterface {

    String generate();

    void save(Tokens token);

    void remove(String secureToken,String username);

    void save(String token, String username, LocalDateTime now, LocalDateTime plusMinutes, String toString);

    List<Tokens> getTokenDetail(String token);

}
