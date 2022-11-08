package example.OnlineTicketBookingSystem.Service;

import example.OnlineTicketBookingSystem.Model.Movie;

import java.util.List;

public interface SystemToCustomerInterface {
    List<Movie> showRunningMovieByName(String movieName, String customerId);
    List<Movie> showRunningMovieByLanguage(String movieLanguage);
    List<Movie> showRunningMovieByGenre(String movieGenre);
    List<Movie> showRunningMovieByCity(String city);
    String getCustomerId(long phoneNumber , String eMail);
}
