package FirstEavluation;

public class Screens {
    private String screenId, movieId, theatreHallId;
    private int numberOfShows, maximumNumberOfSeats;
    private Cinemas cinemas;
    static int[][] seats;

    public int[][] getSeats() {
        return seats;
    }

    public void setSeats(int[][] seats) {
        this.seats = seats;
    }

    public int getMaximumNumberOfSeats() {
        return maximumNumberOfSeats;
    }

    public void setMaximumNumberOfSeats(int maximumNumberOfSeats) {
        this.maximumNumberOfSeats = maximumNumberOfSeats;
    }

    public int getNumberOfShows() {
        return numberOfShows;
    }

    public void setNumberOfShows(int numberOfShows) {
        this.numberOfShows = numberOfShows;
    }

    public Cinemas getCinemas() {
        return cinemas;
    }

    public void setCinemas(Cinemas cinemas) {
        this.cinemas = cinemas;
    }

    public Screens(String screenId, String movieId, String theatreHallId, int numberOfShows, int maximumNumberOfSeats, Cinemas cinemas, int[][] seats) {
        this.screenId = screenId;
        this.movieId = movieId;
        this.theatreHallId = theatreHallId;
        this.numberOfShows = numberOfShows;
        this.maximumNumberOfSeats = maximumNumberOfSeats;
        this.cinemas = cinemas;
        this.seats = seats;
    }

    public String getScreenId() {
        return screenId;
    }

    public void setScreenId(String screenId) {
        this.screenId = screenId;
    }

    public String getMovieId() {
        return movieId;
    }

    public void setMovieId(String movieId) {
        this.movieId = movieId;
    }

    public String getTheatreHallId() {
        return theatreHallId;
    }

    public void setTheatreHallId(String theatreHallId) {
        this.theatreHallId = theatreHallId;
    }

    static void resetAllocatedSeats(int seatNumber, int row, int column) {

                if (seats[row][column] != 0)
                    seats[row][column] = 0;
                else System.out.println("Already seat is allocated.");
    }
}
