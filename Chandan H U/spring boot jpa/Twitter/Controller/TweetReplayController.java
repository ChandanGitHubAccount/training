package Twitter.Controller;

import Twitter.Model.TweetReplay;
import Twitter.Service.TweetReplayInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/replay")
public class TweetReplayController {
    @Autowired
    private TweetReplayInterface tweetReplayInterface;

    @GetMapping("/for-post")
    ResponseEntity<List<TweetReplay>> replayForPost(@RequestParam("tweetId") int tweetId){
        try {
            return ResponseEntity.of(Optional.of(tweetReplayInterface.showReplaysForThePost(tweetId)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
