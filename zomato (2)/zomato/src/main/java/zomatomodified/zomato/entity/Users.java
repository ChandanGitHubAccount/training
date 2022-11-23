package zomatomodified.zomato.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import zomatomodified.zomato.customannottaton.Gender;
import zomatomodified.zomato.customannottaton.PhoneNumber;
import zomatomodified.zomato.customannottaton.Role;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.validation.constraints.Email;
import javax.validation.constraints.Min;
import javax.validation.constraints.Pattern;
import java.time.LocalDate;


@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Users {

    @Id
    private String userId;

    @Pattern(regexp = "^[A-Za-z]+\\s[A-Za-z]+\\s[A-Za-z]+|[A-Za-z]+\\s[A-Za-z]+|[A-Za-z]+$",
            message = "name should contain only alphabet and white space followed by character")
    @Column(nullable = false)
    private String username;

    @Gender
    @Column(nullable = false)
    private String gender;

    @Min(value = 16, message = "minimum age should be 16")
    private int age;

    @PhoneNumber
    @Column(nullable = false, length = 10, unique = true)
    private long phoneNumber;

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

    @Pattern(regexp = "^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$",
            message = "Invalid GST number")
    private String gstNumber;

    private String role;

    private String accountStatus;

    private String profilePhoto;

}
