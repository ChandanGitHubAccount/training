package example.OnlineTicketBookingSystem.Service;

import example.OnlineTicketBookingSystem.Model.BookingStatusOfCustomer;
import example.OnlineTicketBookingSystem.Model.CustomerAccounts;
import example.OnlineTicketBookingSystem.Model.CustomerPaymentDetails;

import java.util.List;

public interface CustomerToSystemInterface {
    List<CustomerAccounts> newCustomerRegistration(CustomerAccounts customerDetails);
    List<BookingStatusOfCustomer> bookingMovieTicket(BookingStatusOfCustomer statusOfCustomer);
    List<CustomerPaymentDetails> makePaymentForBookedSeats(CustomerPaymentDetails paymentDetails);
}
