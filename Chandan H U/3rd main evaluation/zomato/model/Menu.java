package zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Menu {

    private String itemName;

    private String categoryName;

    private String description;

    private int itemPrice;

    private String itemPhoto;

    private String restaurant_id;

}
