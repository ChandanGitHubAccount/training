package zomatomodified.zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class MyOrderItems {

    private String orderId;

    private String itemName;

    private String categoryName;

    private int numberOfItems;

}
