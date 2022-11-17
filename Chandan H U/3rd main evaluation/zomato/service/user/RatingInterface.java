package zomato.service.user;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Favourite;

import java.util.List;

public interface RatingInterface {

    void rating(String orderId) throws SessionIdExpiredException;

    String addToFavourite(String restaurantName) throws SessionIdExpiredException;

    String deleteFavourite(String restaurantName) throws SessionIdExpiredException;

    List<Favourite> viewFavorites() throws SessionIdExpiredException;

}
