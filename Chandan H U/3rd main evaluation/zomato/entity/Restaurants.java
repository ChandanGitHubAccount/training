package zomato.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import zomato.customannottaton.Day;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.validation.constraints.NotBlank;
import java.time.LocalTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class Restaurants {

    @Id
    @Column(nullable = false, length = 10)
    private String restaurantId;

    @NotBlank(message = "Restaurant name cannot be empty")
    @Column(nullable = false, length = 250)
    private String restaurantName;

    @NotBlank(message = "Restaurant name cannot be empty")
    @Column(nullable = false, length = 250)
    private String restaurantAddress;

    private LocalTime openAt;

    private LocalTime closeAt;

    @Day
    private String closeOn;

    private String restaurantPhoto;

    private int ratings;

}
