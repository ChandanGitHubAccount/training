package Twitter.Service;

import Twitter.Model.TweetPosts;
import Twitter.Repository.TweetRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Path;

@Service
public class TweetService implements TweetInterface {
    @Autowired
    private TweetRepository tweetRepository;

    private static final String filePath = "C:\\Users\\Chandan H U\\Desktop\\TweetsPic";
    private int tweetId;

    @Override
    public TweetPosts postTweet(String tweetDescription, MultipartFile tweetPicture) {
        try {
            TweetPosts tweetPosts = new TweetPosts();
            tweetPosts.setTweetDescription(tweetDescription);
            tweetPosts.setTweetPicPath(filePath + File.separator + tweetPicture.getOriginalFilename());
            tweetPicture.transferTo(Path.of(filePath + File.separator + tweetPicture.getOriginalFilename()));
            return tweetRepository.save(tweetPosts);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public String deleteTweet(int tweetId) {
        try {
            tweetRepository.deleteById(tweetId);
            return "Tweet Deleted Successfully";
        } catch (Exception exception) {
            exception.printStackTrace();
            return "Unable to Delete Tweet";
        }
    }

    @Override
    public int numberOfLikesForPost(int tweetId) {
        try {
            return tweetRepository.numberOfLikes(tweetId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return 0;
        }
    }
}
