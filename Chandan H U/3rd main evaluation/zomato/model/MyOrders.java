package zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MyOrders {

    private String orderId;

    private String userId;

    private String restaurantId;

    private LocalDateTime orderDateTime;

    private int totalBill;

    private String paymentMethod;

    private String orderStatus;

}
