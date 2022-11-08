package September9;

import java.util.*;
public class SetExample{
    public static void main(String[] args)
    {
        // creating LinkedHashSet implementation using the Set
        Set<String> marvel_movies = new LinkedHashSet<String>();

        marvel_movies.add("Captain Marvel");
        marvel_movies.add("Thor: Ragnarok");
        marvel_movies.add("Captain America: The Winter Soldier");
        marvel_movies.add("Ant-Man and the Wasp");

        System.out.println(marvel_movies);
    }
}
