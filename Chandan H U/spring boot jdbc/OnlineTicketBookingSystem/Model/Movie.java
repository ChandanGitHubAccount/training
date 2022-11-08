package example.OnlineTicketBookingSystem.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Movie {
    private String movieId,movieTitle,movieLanguage,movieGenre;
    private Date movieReleaseDate;
}
