package Twitter.Service;

import Twitter.Model.TweetPosts;
import Twitter.Model.TweetReplay;

import java.util.List;

public interface TweetReplayInterface {
    List<TweetReplay> showReplaysForThePost(int tweetId);
}
