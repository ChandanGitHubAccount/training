package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.service.user.SearchInterface;

import java.util.Optional;

@RestController
@RequestMapping("/user")
public class SearchController {

    @Autowired
    private SearchInterface searchInterface;

    @GetMapping("/search")
    public ResponseEntity<?> searchField(@RequestPart String field, @RequestParam int pageSize, @RequestParam int pageNumber) {
        return ResponseEntity.of(Optional.of(searchInterface.search(field, pageSize, pageNumber)));
    }
}
