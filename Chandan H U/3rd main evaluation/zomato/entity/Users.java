package zomato.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import zomato.customannottaton.Gender;
import zomato.customannottaton.PhoneNumber;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;
import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Users {

    @Id
    @Column(nullable = false, length = 10)
    private String userId;

    @Pattern(regexp = "^[A-Za-z]+\\s[A-Za-z]+\\s[A-Za-z]+|[A-Za-z]+\\s[A-Za-z]+|[A-Za-z]+$",
            message = "name should contain only alphabet and white space followed by character")
    @Column(nullable = false)
    private String username;

    @Gender
    @Column(nullable = false)
    private String gender;

    @Email(message = "Invalid Email.Please provide valid Email")
    @Column(nullable = false, unique = true)
    private String email;

    @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,250}$",
            message = "Please provide password at least one uppercase letter,one lowercase letter,one number and " +
                    "one special character with minimum length 8 maximum length 250")
    @Column(nullable = false, length = 250)
    private String password;

    @Column(nullable = false)
    private LocalDate createdDate;

    @PhoneNumber
    @Column(nullable = false, length = 10, unique = true)
    private long phoneNumber;

    private String accountStatus;

    private String profilePhoto;

}
