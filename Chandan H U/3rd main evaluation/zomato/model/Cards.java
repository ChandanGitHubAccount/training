package zomato.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import zomato.customannottaton.Card;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Cards {

    private String userId;

    @Card
    private long cardNumber;

}
