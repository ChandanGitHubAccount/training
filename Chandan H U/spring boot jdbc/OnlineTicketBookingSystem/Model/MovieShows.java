package example.OnlineTicketBookingSystem.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.sql.Time;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class MovieShows {
    private String showName;
    private Time movieStartTime,movieEndTime;
}
