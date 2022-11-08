package example.secondmajorevaluation.service;

import example.secondmajorevaluation.model.PassengerDetails;
import example.secondmajorevaluation.model.TicketDetails;
import example.secondmajorevaluation.model.TrainDetails;
import example.secondmajorevaluation.model.TrainStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

@Service
public class PassengerService implements PassengerInterface, Interface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public int generatePassengerId() {
        Random random = new Random();
        StringBuilder Id = new StringBuilder();
        for (int index = 0; index < 4; index++) {
            char number = (char) (49 + random.nextInt(9));
            try {
                Id.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return Integer.parseInt(Id.toString());
    }

    @Override
    public int generateTicketId() {
        Random random = new Random();
        StringBuilder Id = new StringBuilder();
        for (int index = 0; index < 6; index++) {
            char number = (char) (48 + random.nextInt(10));
            try {
                Id.append(number);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        }
        return Integer.parseInt(Id.toString());
    }

    @Override
    public int getWaitIngId(int trainNumber) {
        List<TicketDetails> ticketDetails = jdbcTemplate.query(("select * from ticketDetails where waitingId > 0"),
                new BeanPropertyRowMapper<>(TicketDetails.class));
        return ticketDetails.size() + 1;
    }

    @Override
    public boolean verifyTicketId(int ticketId) {
        List<TicketDetails> ticketDetails = jdbcTemplate.query("Select * from ticketDetails Where ticketId = ?",
                new BeanPropertyRowMapper<>(TicketDetails.class), ticketId);
        return ticketDetails.isEmpty();
    }

    @Override
    public List<String> getRoutOfTrain(int trainNumber) {
        List<String> trainRout = new ArrayList<>();
        List<TrainDetails> trainDetails = jdbcTemplate.query("select * from trainDetails where trainNumber = ?",
                new BeanPropertyRowMapper<>(TrainDetails.class), trainNumber);
        if (!trainDetails.isEmpty()) {
            trainRout.add(trainDetails.get(0).getTrainStartingPoint());
            trainRout.add(trainDetails.get(0).getTrainDestination());
            return trainRout;
        } else return null;
    }

    @Override
    public void updateSeatsInTrainStatus(String bookingOrCanceling, int trainNumber, String coachType, LocalDate date, int numberOfSeatsConfirmed) throws Exception {
        List<TrainStatus> trainStatus = jdbcTemplate.query("select * from trainStatus where trainNumber = ? and coachType = ? and runningDate = ?",
                new BeanPropertyRowMapper<>(TrainStatus.class), trainNumber, coachType, date);
        int numberSeatsLeft;
        int totalNumberOfSeatsBooked;
        try {
            if (bookingOrCanceling.equals(PassengerBookingOrCancelingStatus.Booking.toString())) {
                numberSeatsLeft = trainStatus.get(0).getNumberOfSeats() - numberOfSeatsConfirmed;
                totalNumberOfSeatsBooked = trainStatus.get(0).getNumberOfSeatsBooked() + numberOfSeatsConfirmed;
            } else if (bookingOrCanceling.equals(PassengerBookingOrCancelingStatus.Cancelling.toString())) {
                numberSeatsLeft = trainStatus.get(0).getNumberOfSeats() + numberOfSeatsConfirmed;
                totalNumberOfSeatsBooked = trainStatus.get(0).getNumberOfSeatsBooked() - numberOfSeatsConfirmed;
            } else {
                numberSeatsLeft = trainStatus.get(0).getNumberOfSeats();
                totalNumberOfSeatsBooked = trainStatus.get(0).getNumberOfSeatsBooked();
            }
        } catch (Exception exception) {
            throw new Exception("Invalid choice from passenger.");
        }
        jdbcTemplate.update("update trainStatus set numberOfSeats = ? , numberOfSeatsBooked = ? where trainNumber = ? and coachType = ? and runningDate = ?",
                numberSeatsLeft, totalNumberOfSeatsBooked, trainNumber, coachType, date);
    }

    @Override
    public void updateNumberOfSeatsInTicketDetails(int trainNumber, String coachType, LocalDate date, int numberOfSeatsConfirmed) throws Exception {
        updateSeatsInTrainStatus(PassengerBookingOrCancelingStatus.Booking.toString(), trainNumber, coachType, date, numberOfSeatsConfirmed);
        jdbcTemplate.update("update ticketDetails set numberOfSeats = ? where trainNumber = ? and coachType = ? and bookedDate = ?",
                numberOfSeatsConfirmed, trainNumber, coachType, date);
    }

    @Override
    public boolean checkForSeatAvailability(String coachType, int trainNumber, int numberOfSeats) {
        List<TrainStatus> trainStatus = jdbcTemplate.query("Select * from trainStatus where coachType = ? and trainNumber = ?",
                new BeanPropertyRowMapper<>(TrainStatus.class), coachType, trainNumber);
        return trainStatus.get(0).getNumberOfSeats() >= numberOfSeats;
    }

    @Override
    public boolean checkTrainAvailability(int trainNumber, LocalDate date) {
        List<TrainStatus> trainRunningDates = jdbcTemplate.query("Select * from trainStatus where trainNumber = ? and runningDate = ?",
                new BeanPropertyRowMapper<>(TrainStatus.class), trainNumber, date);
        return trainRunningDates.isEmpty();
    }


    @Override
    public boolean verifyPassengerId(int passengerId) {
        List<PassengerDetails> passengerIds = jdbcTemplate.query("Select * from passengerDetails where passengerId = ?",
                new BeanPropertyRowMapper<>(PassengerDetails.class), passengerId);
        return passengerIds.isEmpty();
    }


    @Override
    public List<PassengerDetails> newPassengerRegistration(PassengerDetails passengerDetails) {
        try {
            int passengerId = generatePassengerId();
            if (!verifyPassengerId(passengerId))
                newPassengerRegistration(passengerDetails);
            jdbcTemplate.update("Insert into passengerDetails values(?,?,?)", passengerId, passengerDetails.getGender(),
                    passengerDetails.getPassengerName());
            return jdbcTemplate.query("select * from passengerDetails where passengerId = ?",
                    new BeanPropertyRowMapper<>(PassengerDetails.class), passengerId);
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public TicketDetails bookTicKet(int numberOfSeatsForBooking, int passengerId, int trainNumber, LocalDate date, String coachType) throws Exception {
        try {
            int ticketId = generateTicketId();
            int ticketAmount;

            if (!verifyTicketId(ticketId))
                bookTicKet(numberOfSeatsForBooking, passengerId, trainNumber, date, coachType);

            if (!checkTrainAvailability(trainNumber, date)) {
                List<String> trainRout = getRoutOfTrain(trainNumber);
                if (coachType.equals("AC"))
                    ticketAmount = 200;
                else
                    ticketAmount = 100;
                if (checkForSeatAvailability(coachType, trainNumber, numberOfSeatsForBooking)) {
                    jdbcTemplate.update("Insert into ticketDetails values(? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ?)", ticketId, coachType,
                            trainRout.get(1), numberOfSeatsForBooking, trainRout.get(0), numberOfSeatsForBooking * ticketAmount, LocalDate.now(), TicketStatus.Confirm.toString(),
                            passengerId, trainNumber, 0);
                    updateNumberOfSeatsInTicketDetails(trainNumber, coachType, date, numberOfSeatsForBooking);
                } else {
                    jdbcTemplate.update("Insert into ticketDetails values(? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ?)", ticketId, coachType,
                            trainRout.get(1), numberOfSeatsForBooking, trainRout.get(0), numberOfSeatsForBooking * ticketAmount, LocalDate.now(), TicketStatus.Waiting.toString(),
                            passengerId, trainNumber, getWaitIngId(trainNumber));
                }
                return getBookedTicketDetails(ticketId);
            } else
                return null;
        } catch (Exception exception) {
            throw new Exception("Invalid Details");
        }
    }

    @Override
    public TicketDetails getBookedTicketDetails(int ticketId) {
        return jdbcTemplate.query("Select * from ticketDetails where ticketId = ?",
                new BeanPropertyRowMapper<>(TicketDetails.class), ticketId).get(0);
    }

    @Override
    public String unregisterPassenger(int passengerId) {
        jdbcTemplate.update("delete from passengerDetails where passengerId = ?", passengerId);
        return "UnRegistration Successful";
    }

    @Override
    public String cancelBookedTicket(int ticketId) throws Exception {
        TicketDetails ticketDetails = getBookedTicketDetails(ticketId);
        if (ticketDetails.getBookedDate().compareTo(LocalDate.now()) < 0) {
            updateSeatsInTrainStatus(PassengerBookingOrCancelingStatus.Cancelling.toString(), ticketDetails.getTrainNumber(),
                    ticketDetails.getCoachType(), ticketDetails.getBookedDate(), ticketDetails.getNumberOfSeats());
            jdbcTemplate.update("update ticketDetails set ticketStatus = ? where ticketId = ?", TicketStatus.Cancelled.toString(),
                    ticketId);
            confirmWaitingPassengerTicket();
            return "Ticket canceled Successfully.";
        } else return "Unable to cancel ticket because ticket date is Expired.";
    }

    @Override
    public String confirmWaitingPassengerTicket() throws Exception {
        List<TicketDetails> ticketDetails = jdbcTemplate.query("Select * from ticketDetails where waitingId > 0 order by waitingId",
                new BeanPropertyRowMapper<>(TicketDetails.class));
        for (TicketDetails ticketDetail : ticketDetails) {
            if (checkForSeatAvailability(ticketDetail.getCoachType(), ticketDetail.getTrainNumber(), ticketDetail.getNumberOfSeats())) {
                jdbcTemplate.update("update set ticketStatus = ? , waitingId = 0 where ticketId = ?", TicketStatus.Confirm.toString(),
                        ticketDetail.getTicketId());
                updateSeatsInTrainStatus(PassengerBookingOrCancelingStatus.Booking.toString(), ticketDetail.getTrainNumber(),
                        ticketDetail.getCoachType(), ticketDetail.getBookedDate(), ticketDetail.getNumberOfSeats());
                return "Waiting Passenger with Ticket Id : " + ticketDetail.getTicketId() + " is Confirmed";
            }
        }
        return null;
    }


}
