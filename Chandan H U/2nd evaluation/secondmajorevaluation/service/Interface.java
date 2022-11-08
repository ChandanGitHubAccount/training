package example.secondmajorevaluation.service;

import java.time.LocalDate;
import java.util.List;

public interface Interface {
    int generatePassengerId();

    boolean verifyPassengerId(int passengerId);

    int generateTicketId();

    int getWaitIngId(int trainNumber);

    boolean checkForSeatAvailability(String coachType, int trainNumber,int numberOfSeats);

    boolean verifyTicketId(int ticketId);

    List<String> getRoutOfTrain(int trainNumber);

    void updateSeatsInTrainStatus(String bookingOrCanceling , int trainNumber, String coachType, LocalDate date, int numberOfSeatsConfirmed) throws Exception;

    void updateNumberOfSeatsInTicketDetails(int trainNumber, String coachType, LocalDate date, int numberOfSeatsConfirmed) throws Exception;
    String confirmWaitingPassengerTicket() throws Exception;
}
