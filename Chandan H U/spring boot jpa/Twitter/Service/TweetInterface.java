package Twitter.Service;

import Twitter.Model.TweetPosts;
import org.springframework.web.multipart.MultipartFile;

public interface TweetInterface {
    TweetPosts postTweet(String tweetDescription , MultipartFile tweetPicture);
    String deleteTweet(int tweetId);

    int numberOfLikesForPost(int tweetId);
}
