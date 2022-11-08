package example.OnlineTicketBookingSystem.Model;

import lombok.*;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CustomerAccounts {
    private String customerId;
    @NotNull(message = "Name cannot be null please provide the proper name.")
    private String customerName;
    @Email(message = "Invalid email please provide the proper name.")
    private String customerEmail ;
    @NotNull(message = "Name cannot be null please provide the proper name.")
    private String customerAddress;
    @Pattern(regexp = "^[0-9]{10}$",message = "Invalid number.Please provide 10 digit number")
    private long customerPhoneNumber;
}
