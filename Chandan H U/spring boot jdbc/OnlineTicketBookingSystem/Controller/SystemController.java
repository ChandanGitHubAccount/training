package example.OnlineTicketBookingSystem.Controller;

import example.OnlineTicketBookingSystem.Model.BookingStatusOfCustomer;
import example.OnlineTicketBookingSystem.Model.CustomerAccounts;
import example.OnlineTicketBookingSystem.Model.CustomerPaymentDetails;
import example.OnlineTicketBookingSystem.Model.Movie;
import example.OnlineTicketBookingSystem.Service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
public class SystemController {
    @Autowired
    SystemToCustomerInterface systemToCustomerInterface;
    @Autowired
    OnlineSystemInterface onlineSystemInterface;
    @Autowired
    CustomerToSystemInterface customerToSystemInterface;

    @GetMapping("movieByName/{movieName}/{customerId}")
    ResponseEntity<List<Movie>> SearchMovieByName(@PathVariable String movieName, @PathVariable String customerId) {
        try {
            return ResponseEntity.of(Optional.of(systemToCustomerInterface.showRunningMovieByName(movieName, customerId)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("movieByGenre/{movieGenre}")
    ResponseEntity<List<Movie>> SearchMovieByGenre(@PathVariable String movieGenre) {
        try {
            return ResponseEntity.of(Optional.of(systemToCustomerInterface.showRunningMovieByGenre(movieGenre)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("movieByLanguage/{movieLanguage}")
    ResponseEntity<List<Movie>> SearchMovieByLanguage(@PathVariable String movieLanguage) {
        try {
            return ResponseEntity.of(Optional.of(systemToCustomerInterface.showRunningMovieByLanguage(movieLanguage)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("movieCity/{cityName}")
    ResponseEntity<List<Movie>> SearchMovieByCityName(@PathVariable String cityName) {
        try {
            return ResponseEntity.of(Optional.of(systemToCustomerInterface.showRunningMovieByCity(cityName)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("getCustomerGetId/{phoneNumber}/{eMail}")
    ResponseEntity<String> getCustomerId(@PathVariable long phoneNumber, @PathVariable String eMail) {
        try{
            return ResponseEntity.of(Optional.of(systemToCustomerInterface.getCustomerId(phoneNumber, eMail)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("getBookingDetails/")
    ResponseEntity<List<BookingStatusOfCustomer>> getBookingDetails(@RequestBody BookingStatusOfCustomer bookingDetails) {
        try{
            return ResponseEntity.of(Optional.of(customerToSystemInterface.bookingMovieTicket(bookingDetails)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("getPaymentDetails/")
    ResponseEntity<List<CustomerPaymentDetails>> getPaymentDetails(@RequestBody CustomerPaymentDetails paymentDetails) {
        try{
            return ResponseEntity.of(Optional.of(customerToSystemInterface.makePaymentForBookedSeats(paymentDetails)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("newRegistration/")
    ResponseEntity<List<CustomerAccounts>> newRegistration(@RequestBody CustomerAccounts customerDetails) {
        try{
            return ResponseEntity.of(Optional.of(customerToSystemInterface.newCustomerRegistration(customerDetails)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("availableShowNames/")
    ResponseEntity<List<ShowNames>> availableShowNames() {
        try{
            return ResponseEntity.of(Optional.of(onlineSystemInterface.viewAvailableShows()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("availablePaymentMethods/")
    ResponseEntity<List<TypeOfPayment>> availablePaymentMethods() {
        try{
            return ResponseEntity.of(Optional.of(onlineSystemInterface.typeOfPaymentAvailable()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("verifyCustomerId/{customerId}")
    ResponseEntity<String> verifyCustomerId(@PathVariable String customerId) {
        try{
            if (onlineSystemInterface.verifyCustomerId(customerId))
                return ResponseEntity.of(Optional.of("Invalid Customer Id."));
            else  return ResponseEntity.of(Optional.of("Customer Id is registered."));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("verifyBookingId/{bookingId}")
    ResponseEntity<String> verifyBookingId(@PathVariable int bookingId){
        try{
            if(onlineSystemInterface.verifyBookingId(bookingId))
                return ResponseEntity.of(Optional.of("Invalid Booking Id."));
            else return ResponseEntity.of(Optional.of("Valid Booking Id."));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
