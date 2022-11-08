package Twitter.Repository;

import Twitter.Model.TwitterUsers;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Repository
@Transactional
public interface TwitterUserRepository extends JpaRepository<TwitterUsers, Integer> {
    List<TwitterUsers> findByUserIdAndUserPassword(int userId, String userPassword);

    @Modifying
    @Query(value = "UPDATE twitter_users SET profile_picture = :profilePicture WHERE user_id = :loggedUser",nativeQuery = true)
    void changeProfilePhoto(@Param("profilePicture") String profilePicture, @Param("loggedUser") int loggedUser);
}
