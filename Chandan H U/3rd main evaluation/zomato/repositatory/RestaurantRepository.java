package zomato.repositatory;

import org.springframework.data.jpa.repository.JpaRepository;
import zomato.entity.Restaurants;

import java.util.List;

public interface RestaurantRepository extends JpaRepository<Restaurants, String> {

    List<Restaurants> findByRestaurantName(String restaurantName);

    List<Restaurants> findByRestaurantAddress(String restaurantAddress);

    List<Restaurants> findByRestaurantId(String restaurantId);
}
