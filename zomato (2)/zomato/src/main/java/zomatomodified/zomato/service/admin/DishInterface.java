package zomatomodified.zomato.service.admin;

import org.springframework.web.multipart.MultipartFile;
import zomatomodified.zomato.coustomexcptions.UpdateFailedException;
import zomatomodified.zomato.model.Dish;

import java.io.IOException;
import java.util.List;

public interface DishInterface {

    String addDish(List<Dish> dish);

    String editDish(Dish dish) throws UpdateFailedException;

    String changeDishPhoto(String itemId, MultipartFile dishPhoto) throws UpdateFailedException, IOException;

    String removeDish(String itemId) throws UpdateFailedException;

    String deleteDishPhoto(String itemId) throws IOException;

}
