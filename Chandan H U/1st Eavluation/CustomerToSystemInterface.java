package FirstEavluation;

public interface CustomerToSystemInterface {
    void searchMoviesByMovieName(String movieName, String customerId);
    void searchMoviesByCityName(String cityName, String customerId);
    void searchMoviesByMovieGenre(String genre, String customerId);
    void searchMoviesByMovieLanguage(String language, String customerId);
    int makePaymentToBookTicket(int numberOfSeats , String paymentMethod);
    void selectParticularShows(String key, String customerId);
    void chooseSeats(String key);
}
