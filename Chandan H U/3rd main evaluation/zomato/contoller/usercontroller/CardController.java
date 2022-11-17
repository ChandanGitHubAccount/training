package zomato.contoller.usercontroller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Cards;
import zomato.service.user.CardInterface;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class CardController {

    /**
     * ******Cards Controller ******
     */

    @Autowired
    private CardInterface cardInterface;

    @PostMapping("/add-card")
    public ResponseEntity<String> addCards(@RequestParam @Valid long cardNumber) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(cardInterface.addCards(cardNumber)));
    }

    @GetMapping("/view-cards")
    public ResponseEntity<List<Cards>> viewAllCards() throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(cardInterface.viewAllCards()));
    }

    @DeleteMapping("/remove-card")
    public ResponseEntity<String> removeCard(@RequestParam long cardNumber) throws SessionIdExpiredException {
        return ResponseEntity.of(Optional.of(cardInterface.removeCard(cardNumber)));
    }

}
