package Twitter.Service;

import Twitter.Model.TweetPosts;
import Twitter.Model.TweetReplay;
import Twitter.Repository.TweetReplayRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TweetReplayServices implements TweetReplayInterface {

    @Autowired
    private TweetReplayRepository tweetReplayRepository;

    @Override
    public List<TweetReplay> showReplaysForThePost(int tweetId) {
        try {
            return tweetReplayRepository.showReplayForPosts(tweetId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }
}
