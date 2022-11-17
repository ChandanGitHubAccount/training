package zomato.service.restaurant;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Categories;

import java.util.List;

public interface CategoryInterface {

    String addCategories(List<Categories> categories) throws SessionIdExpiredException;

    String changeDeliveryCharge(int deliveryCharge , String categoryName) throws SessionIdExpiredException;

    String removeCategory(String categoryName) throws SessionIdExpiredException;

    List<Categories> viewCategories() throws SessionIdExpiredException;

    Categories getParticularCategory(String categoryName) throws SessionIdExpiredException;

}
