package zomato.repositatory;

import org.springframework.data.jpa.repository.JpaRepository;
import zomato.entity.Users;

import java.util.List;

public interface UserRepository extends JpaRepository<Users, String> {

    List<Users> findByUserId(String userId);

    List<Users> findByEmailOrPhoneNumber(String email, long phoneNumber);

    List<Users> findByEmailAndPassword(String email, String password);

    List<Users> findByEmail(String email);
}
