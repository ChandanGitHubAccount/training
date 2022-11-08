package Twitter.Repository;

import Twitter.Model.TweetPosts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public interface TweetRepository extends JpaRepository<TweetPosts, Integer> {

    @Query(value = "SELECT like_count FROM tweet_posts WHERE tweet_id = :tweetId",nativeQuery = true)
    int numberOfLikes(@Param("tweetId") int tweetId);
}
