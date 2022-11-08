package Twitter.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "twitterUsers", schema = "twitter")
public class TwitterUsers {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int userId;

    @Column(name = "userName", nullable = false)
    private String userName;

    @Column(name = "userDescriptions")
    private String userDescriptions;

    @Column(name = "createdDate", nullable = false)
    private LocalDate createdDate = LocalDate.now();

    @Column(name = "profilePicture")
    private String profilePicturePath;

    @Column(name = "password", nullable = false)
    private String userPassword;

    @Column(name = "accountType", nullable = false)
    private String accountType;

    @Column(name = "gender",nullable = false)
    private String userGender;

    @OneToMany(mappedBy = "twitterUsers", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<TweetPosts> tweetPosts;

    @OneToMany(mappedBy = "twitterUsers",cascade = CascadeType.ALL)
    @JsonIgnore
    private List<TweetReplay> tweetReplays;

   /* @OneToMany(mappedBy = "twitterUsersId", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<UserFollowers> userFollowers;

    @OneToMany(mappedBy = "twitterUsersId", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<UserFollowing> userFollowings;*/

}
