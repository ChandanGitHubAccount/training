package example.OnlineTicketBookingSystem.Service;

import example.OnlineTicketBookingSystem.Model.Movie;

import java.util.List;

public interface OnlineSystemInterface {
    String generateCustomerId();
    int generatePaymentIdOrBookingId();
    boolean verifyCustomerId(String customerId);
    boolean verifyBookingId(int bookingId);
    List<ShowNames> viewAvailableShows();
    List<TypeOfPayment> typeOfPaymentAvailable();
    boolean verifyForEmptySeatAvailability(String theatreId);
}
