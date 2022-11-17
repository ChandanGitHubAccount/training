package zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import zomato.customannottaton.Payments;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Payment {

    @Payments
    String paymentType;

    String restaurantId;
}
