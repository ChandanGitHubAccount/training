package zomatomodified.zomato.service.user;

import zomatomodified.zomato.model.Favourites;
import zomatomodified.zomato.model.Restaurants;

import java.util.List;

public interface RatingInterface {

    void rating(String orderId) ;

    String addToFavourite(String restaurantId);

    String deleteFavourite(String restaurantName) ;

    List<Restaurants> viewFavorites() ;
}
