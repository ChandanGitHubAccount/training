package example.SpringBoot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	/*List<String> movieId;
	movieId = jdbcTemplate.query("select distinct movieid from screens where theatreid in (select theatreId from theatre where cityid in (select cityid from city where cityname = 'hassan'))",new BeanPropertyRowMapper<>(String.class));
		System.out.println(movieId);*/
	}
}
