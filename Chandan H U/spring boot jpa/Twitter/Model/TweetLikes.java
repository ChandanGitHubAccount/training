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
@Table(name = "likes")
public class TweetLikes {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int likeId;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "tweetId",updatable = false,insertable = false)
    private TweetPosts tweetPosts;

}
