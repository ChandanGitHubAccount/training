package example.secondmajorevaluation.service;

import example.secondmajorevaluation.model.PassengerDetails;
import example.secondmajorevaluation.model.TicketDetails;

import java.time.LocalDate;
import java.util.List;

public interface PassengerInterface {
    List<PassengerDetails> newPassengerRegistration(PassengerDetails passengerDetails) throws ClassNotFoundException;

    boolean checkTrainAvailability(int trainNumber, LocalDate date);

    TicketDetails bookTicKet(int numberOfSeatsForBooking , int passengerId, int trainNumber, LocalDate date,String coachType) throws Exception;

    String cancelBookedTicket(int ticketId) throws Exception;

    TicketDetails getBookedTicketDetails(int ticketId);

    String unregisterPassenger(int passengerId);
}

