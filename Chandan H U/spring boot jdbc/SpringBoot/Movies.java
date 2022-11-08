package example.SpringBoot;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Movies {
    private String movieId,movieTitle,movieLanguage,movieGenre;
    private Date movieReleaseDate;
}
