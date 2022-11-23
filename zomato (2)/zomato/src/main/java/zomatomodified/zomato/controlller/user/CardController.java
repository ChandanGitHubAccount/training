package zomatomodified.zomato.controlller.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomatomodified.zomato.coustomexcptions.InvalidCardNumberException;
import zomatomodified.zomato.model.Cards;
import zomatomodified.zomato.service.user.CardInterface;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user/card")
public class CardController {

    /**
     * ******Cards Controller ******
     */

    @Autowired
    private CardInterface cardInterface;

    @PostMapping("/add-card")
    public ResponseEntity<String> addCards(@RequestHeader long cardNumber) throws InvalidCardNumberException {
        return ResponseEntity.of(Optional.of(cardInterface.addCards(cardNumber)));
    }

    @GetMapping("/view-cards")
    public ResponseEntity<List<Cards>> viewAllCards() {
        return ResponseEntity.of(Optional.of(cardInterface.viewAllCards()));
    }

    @DeleteMapping("/remove-card")
    public ResponseEntity<String> removeCard(@RequestHeader long cardNumber) throws InvalidCardNumberException {
        return ResponseEntity.of(Optional.of(cardInterface.removeCard(cardNumber)));
    }
}
