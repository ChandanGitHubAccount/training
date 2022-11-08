package example.OnlineTicketBookingSystem.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BookingStatusOfCustomer {
    private int bookingNumber,currentNumberOfSeatsBooked;
    private String customerId,showName,theatreId;
}
