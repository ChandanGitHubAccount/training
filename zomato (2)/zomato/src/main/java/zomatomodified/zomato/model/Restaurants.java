package zomatomodified.zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import zomatomodified.zomato.customannottaton.Day;

import javax.validation.constraints.NotBlank;
import java.time.LocalTime;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Restaurants {

    private String restaurantId;

    private String userId;

    @NotBlank(message = "Restaurant name cannot be empty")
    private String restaurantName;

    @NotBlank(message = "Restaurant address cannot be empty")
    private String restaurantAddress;

    @NotBlank(message = "open time cannot be empty")
    private LocalTime openAt;

    @NotBlank(message = "close time cannot be empty")
    private LocalTime closeAt;

    @Day
    private String closeOn;

    @NotBlank(message = "delivery Charge cannot be empty")
    private int deliveryCharge;

    private int ratings;

    private String restaurantPhoto;

}
