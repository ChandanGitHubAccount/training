package FirstEavluation;

import java.util.Map;

public interface AdminToSystemInterface {
    void displayTheatresWhereMoviesWillRun(Map<String, City> city);
    void addOrModifyMovie(String choice, Map<String, City> city);
}
