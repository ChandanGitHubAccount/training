package Twitter.Repository;

import Twitter.Model.TweetReplay;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
public interface TweetReplayRepository extends JpaRepository<TweetReplay, Integer> {
    @Query(value = "SELECT * FROM tweet_replay WHERE tweet_id = :tweetId", nativeQuery = true)
    List<TweetReplay> showReplayForPosts(@Param("tweetId") int tweetId);

}
