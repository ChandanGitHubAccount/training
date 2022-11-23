package zomatomodified.zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RestaurantOrders {

    private String restaurantId;

    private String orderId;

    private int totalBill;

    private LocalDate orderDate;
}