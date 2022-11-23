package zomatomodified.zomato.service.user;

import zomatomodified.zomato.coustomexcptions.InvalidCardNumberException;
import zomatomodified.zomato.model.Cards;

import java.util.List;

public interface CardInterface {
    String addCards(long cardNumber) throws InvalidCardNumberException;

    String removeCard(long cardNumber) throws InvalidCardNumberException;

    List<Cards> viewAllCards() ;

}
