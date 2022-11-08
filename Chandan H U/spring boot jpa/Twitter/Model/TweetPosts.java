package Twitter.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "tweets", schema = "twitter")
public class TweetPosts {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int tweetId;

    @Column(name = "tweetDescription")
    private String tweetDescription;

    @Column(name = "tweetPicPath")
    private String tweetPicPath;

    @Column(name = "likeCount")
    private int likeCount;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "userId", insertable = false, updatable = false)
    private TwitterUsers twitterUsers;

    @OneToMany(cascade = CascadeType.ALL,mappedBy = "tweetPosts")
    @JsonIgnore
    private List<TweetLikes> likes;

    @OneToMany(cascade = CascadeType.ALL,mappedBy = "tweetPosts")
    @JsonIgnore
    private  List<TweetReplay> tweetReplays;

}
