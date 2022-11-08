package FirstEavluation;

import java.util.Map;
import java.util.Scanner;

public class Admins implements AdminToSystemInterface {
    static Scanner scan = new Scanner(System.in);
    @Override
    public void displayTheatresWhereMoviesWillRun(Map<String, City> city) {
        for(String key : city.keySet())
            System.out.println(city.get(key).getTheatreHalls().toString());
    }
    @Override
    public void addOrModifyMovie(String cityId, Map<String, City> city) {
        System.out.println("Enter new movie name,language and genre to change old movie.");
        String movieId = city.get(cityId).getTheatreHalls().getScreens().getCinemas().getMovieId();
        String newMovieName = scan.next();
        String language = scan.next();
        String genre = scan.next();
        city.get(cityId).getTheatreHalls().getScreens().setCinemas(new Cinemas(movieId,newMovieName,language,genre));
    }
}
