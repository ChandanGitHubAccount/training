package zomato.service.user;

import zomato.coustomexcptions.SessionIdExpiredException;
import zomato.model.Cards;

import java.util.List;

public interface CardInterface {

    String addCards(long cardNumber) throws SessionIdExpiredException;

    String removeCard(long cardNumber) throws SessionIdExpiredException;

    List<Cards> viewAllCards() throws SessionIdExpiredException;

}
