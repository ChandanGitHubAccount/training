package example.secondmajorevaluation.controller;

import example.secondmajorevaluation.model.PassengerDetails;
import example.secondmajorevaluation.model.TicketDetails;
import example.secondmajorevaluation.service.PassengerInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/passenger")
public class PassengerController {

    @Autowired
    private PassengerInterface passengerInterface;

    @PostMapping("/registration")
    ResponseEntity<List<PassengerDetails>> addPassenger(@RequestBody PassengerDetails passengerDetail) {
        try {
            return ResponseEntity.of(Optional.of(passengerInterface.newPassengerRegistration(passengerDetail)));
        } catch (ClassNotFoundException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/check-for-train-availability")
    ResponseEntity<String> checkForTrainAvailability(@RequestParam int trainNumber, @RequestParam
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date) {
        try {
            passengerInterface.checkTrainAvailability(trainNumber, date);
            return new ResponseEntity<>("Train is available for booking.", HttpStatus.OK);
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @PostMapping("/book-ticket")
    ResponseEntity<TicketDetails> bookTrainTicket(@RequestParam int numberOfSeatsForBooking, @RequestParam int passengerId,
                                                  @RequestParam int trainNumber, @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate date,
                                                  @RequestParam String coachType) {
        try {
            return ResponseEntity.of(Optional.of(passengerInterface.bookTicKet(numberOfSeatsForBooking, passengerId, trainNumber, date, coachType)));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("/cancel-ticket")
    ResponseEntity<String> cancelTrainTicket(@RequestParam int ticketId) {
        try {
            return ResponseEntity.of(Optional.of(passengerInterface.cancelBookedTicket(ticketId)));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/get-booked-train-ticket")
    ResponseEntity<TicketDetails> getBookedTrainTicket(@RequestParam int ticketId) {
        try {
            return ResponseEntity.of(Optional.of(passengerInterface.getBookedTicketDetails(ticketId)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @DeleteMapping("/unregister")
    ResponseEntity<String> unregisterPassenger(@RequestParam int passengerId) {
        try {
            return ResponseEntity.of(Optional.of(passengerInterface.unregisterPassenger(passengerId)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
