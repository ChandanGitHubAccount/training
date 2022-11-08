package FirstEavluation;

public class Cinemas {
    private String movieId , nameOfMovie , movieLanguage , genre;

    public String getGenre() {
        return genre;
    }

    public void setGenre(String genre) {
        this.genre = genre;
    }

    public Cinemas(String movieId, String nameOfMovie, String movieLanguage, String genre) {
        this.movieId = movieId;
        this.nameOfMovie = nameOfMovie;
        this.movieLanguage = movieLanguage;
        this.genre = genre;
    }

    public String getMovieLanguage() {
        return movieLanguage;
    }

    public void setMovieLanguage(String movieLanguage) {
        this.movieLanguage = movieLanguage;
    }

    public String getMovieId() {
        return movieId;
    }

    public void setMovieId(String movieId) {
        this.movieId = movieId;
    }

    public String getNameOfMovie() {
        return nameOfMovie;
    }

    public void setNameOfMovie(String nameOfMovie) {
        this.nameOfMovie = nameOfMovie;
    }

    @Override
    public String toString() {
        return "Cinemas{" +
                "movieId='" + movieId + '\'' +
                ", nameOfMovie='" + nameOfMovie + '\'' +
                ", movieLanguage='" + movieLanguage + '\'' +
                ", genre='" + genre + '\'' +
                '}';
    }
}
