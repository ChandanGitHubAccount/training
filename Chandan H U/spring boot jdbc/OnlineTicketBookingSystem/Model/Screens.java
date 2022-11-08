package example.OnlineTicketBookingSystem.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Screens {
    private String screenId,theatreId,movieId;
    private int numberOfShows,maximumNumberOfSeats;
}
