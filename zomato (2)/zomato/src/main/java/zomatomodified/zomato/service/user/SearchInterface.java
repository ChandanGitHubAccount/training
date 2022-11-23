package zomatomodified.zomato.service.user;

import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

public interface SearchInterface {
    List<?> search(String field,int pageSize,int pageNumber);
}
