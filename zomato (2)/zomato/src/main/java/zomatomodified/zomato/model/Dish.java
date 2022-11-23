package zomatomodified.zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotBlank;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Dish {

    private String itemId;

    @NotBlank(message = "field cannot be empty")
    private String restaurantId;

    @NotBlank(message = "field cannot be empty")
    private String categoryId;

    @NotBlank(message = "field cannot be empty")
    private String  menuId;

    @NotBlank(message = "field cannot be empty")
    private String itemName;

    @NotBlank(message = "field cannot be empty")
    private int itemPrice;

    private String description;

    private String itemPhoto;



}
