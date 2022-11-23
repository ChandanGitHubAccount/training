package zomatomodified.zomato.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import zomatomodified.zomato.entity.Users;

import java.util.List;

public interface UserRepository extends JpaRepository<Users, String> {

    List<Users> findByEmail(String email);

    List<Users> findByEmailAndPassword(String email, String password);

    List<Users> findByEmailOrPhoneNumber(String email, long phoneNumber);

    List<Users> findByUserId(String userId);
}
