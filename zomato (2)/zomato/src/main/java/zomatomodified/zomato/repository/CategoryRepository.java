package zomatomodified.zomato.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import zomatomodified.zomato.entity.Categories;

import java.util.List;

public interface CategoryRepository extends JpaRepository<Categories,String> {
    List<Categories> findByCategoryName (String categoryName);

    List<Categories> findByCategoryId (String categoryId);
}
