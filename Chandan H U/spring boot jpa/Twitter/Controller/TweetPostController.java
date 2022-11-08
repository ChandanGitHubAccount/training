package Twitter.Controller;

import Twitter.Model.TweetPosts;
import Twitter.Service.TweetInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Optional;

@RestController
@RequestMapping("/tweet")
public class TweetPostController {
    @Autowired
    private TweetInterface tweetInterface;

    @PostMapping("/post-tweets")
    ResponseEntity<TweetPosts> postTweet(@RequestParam("postDescription") String postDescription , @RequestParam("postPic")MultipartFile postPic){
        try {
            return ResponseEntity.of(Optional.of(tweetInterface.postTweet(postDescription,postPic)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @DeleteMapping("/delete-post")
    ResponseEntity<String > deleteTweetPost(@RequestParam("tweetId") int tweetId){
        try {
            return ResponseEntity.of(Optional.of(tweetInterface.deleteTweet(tweetId)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
    @GetMapping("/number-of-likes")
    ResponseEntity<Integer> numberOfLikes(@RequestParam("tweetId") int tweetId){
        try {
            return ResponseEntity.of(Optional.of(tweetInterface.numberOfLikesForPost(tweetId)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }
}
