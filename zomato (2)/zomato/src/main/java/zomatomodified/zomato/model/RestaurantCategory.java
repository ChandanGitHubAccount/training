package zomatomodified.zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RestaurantCategory {

    private String categoryId;

    private String  menuId;

    private String restaurantId;

}
