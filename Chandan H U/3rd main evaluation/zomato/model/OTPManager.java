package zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.Email;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class OTPManager {

    private String userId;

    @Email(message = "Invalid Email.Please provide valid Email")
    private String email;

    private int otp;

}
