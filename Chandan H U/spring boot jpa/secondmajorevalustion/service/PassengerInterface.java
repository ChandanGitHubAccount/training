package secondmajorevalustion.service;

import secondmajorevalustion.model.PassengerDetails;
import secondmajorevalustion.model.TicketDetails;
import secondmajorevalustion.model.TrainRunningDates;

public interface PassengerInterface {
    PassengerDetails addPassenger(PassengerDetails passengerDetails);

    String checkTrainAvailability(int trainNumber, TrainRunningDates date);

    TicketDetails bookTicKet(int numberOfSeatsForBooking , int passengerId,int trainNumber, TrainRunningDates date);
}
