package secondmajorevalustion.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import secondmajorevalustion.model.PassengerDetails;
import secondmajorevalustion.model.TicketDetails;
import secondmajorevalustion.model.TrainDetails;
import secondmajorevalustion.model.TrainRunningDates;
import secondmajorevalustion.repository.*;

import java.util.List;

@Service
public class PassengerService implements PassengerInterface{

    @Autowired
    private PassengerRepository passengerRepository;
    @Autowired
    private TicketRepository ticketRepository;
    @Autowired
    private WaitingRepository waitingRepository;
    @Autowired
    private TrainRepository trainRepository;
    @Autowired
    private TrainRunningDateRepository trainRunningDateRepository;

    @Override
    public PassengerDetails addPassenger(PassengerDetails passengerDetails) {
        try {
            return passengerRepository.save(passengerDetails);
        }catch (Exception exception){
            throw new RuntimeException("InValid details");
        }
    }

    @Override
    public String checkTrainAvailability(int trainNumber, TrainRunningDates date) {
        try {
            List<TrainDetails> trainDetails = trainRepository.findByTrainNumberAndTrainRunningDates(trainNumber,date);
            if (trainDetails.isEmpty())
                return "Invalid Train Number/Date";
            else
                return "Train Available";
        }catch (Exception exception){
            throw new RuntimeException("Invalid Data");
        }
    }

    @Override
    public TicketDetails bookTicKet(int numberOfSeatsForBooking, int passengerId, int trainNumber, TrainRunningDates date) {
        if(checkTrainAvailability(trainNumber,date).equals("Train Available")){
            TicketDetails ticketDetails = new TicketDetails();
            ticketDetails.setPassengerDetails(passengerRepository.findById(passengerId).get());
            ticketDetails.setTicketAmount(numberOfSeatsForBooking*150);
        }
    }
}
