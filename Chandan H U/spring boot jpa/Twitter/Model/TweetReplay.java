package Twitter.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "Replay")
public class TweetReplay {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int replayId;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "tweetId", insertable = false, updatable = false)
    private TweetPosts tweetPosts;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "userId",insertable = false,updatable = false)
    private TwitterUsers twitterUsers;

}
