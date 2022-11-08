/*
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
@Table(name = "userFollowers")
public class UserFollowers {

    private int UserFollowersId;

    @Id
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "userId" , updatable = false,insertable = false)
    private TwitterUsers twitterUsersId;

}
*/
