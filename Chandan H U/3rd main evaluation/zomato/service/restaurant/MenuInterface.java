package zomato.service.restaurant;

import org.springframework.web.multipart.MultipartFile;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.coustomexcptions.UpdateFailedException;
import zomato.model.Menu;

import java.io.IOException;

public interface MenuInterface {

    String addMenu(Menu menu, MultipartFile dishPhoto) throws SessionIdExpiredException, IOException;

    String changeDescription(String itemName, String categoryName, String description) throws SessionIdExpiredException, UpdateFailedException;

    String changeDishPhoto(String itemName, String categoryName, MultipartFile dishPhoto) throws SessionIdExpiredException, UpdateFailedException, IOException;

    String changeDishPrice(String itemName, String categoryName, int itemPrice) throws SessionIdExpiredException, UpdateFailedException;

    String changeCategory(String itemName, String oldCategoryName, String newCategoryName) throws SessionIdExpiredException, UpdateFailedException;

    String removeMenu(String itemName , String categoryName) throws UpdateFailedException, SessionIdExpiredException;

    String deleteOldPhoto(String itemName, String categoryName) throws IOException, SessionIdExpiredException;

}
