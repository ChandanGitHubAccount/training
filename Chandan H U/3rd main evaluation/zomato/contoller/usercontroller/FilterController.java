package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.service.user.FilterInterface;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user/filter")
public class FilterController {

    /**
     * ******Filter Controller******
     */

    @Autowired
    private FilterInterface filterInterface;

    @GetMapping("/view-sort-option")
    public ResponseEntity<List<String>> viewSortOption() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(filterInterface.viewSortOptions()));
    }

    @GetMapping("/view-payment-type")
    public ResponseEntity<List<String>> viewPaymentType() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(filterInterface.showPaymentType()));
    }

    @GetMapping("/view-other-filters")
    public ResponseEntity<List<String>> viewOtherFilters() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(filterInterface.otherFilters()));
    }

    @GetMapping("/filtered-result")
    public ResponseEntity<List<?>> viewFilteredResult(@RequestParam String categoryName, @RequestParam String sortBy,
                                                      @RequestParam int priceRange, @RequestParam boolean openNow,
                                                      @RequestParam String paymentType, @RequestParam boolean freeDelivery,
                                                      @RequestParam int pageSize, @RequestParam int pageNumber) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(filterInterface.filterAll(categoryName, sortBy,
                priceRange, openNow, paymentType, freeDelivery, pageSize, pageNumber)));
    }

}
