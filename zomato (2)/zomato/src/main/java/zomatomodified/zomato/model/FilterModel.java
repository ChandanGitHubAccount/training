package zomatomodified.zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class FilterModel {
    String categoryId = null;
    String sortBy = null;
    int priceRange = 0;
    boolean openNow = false;
    boolean isCreditCard = false;
    boolean freeDelivery = false;
}
