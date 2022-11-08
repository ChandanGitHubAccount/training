package example.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
	/*@Override
	public void run(String[] args) {
		// Print statement when method is called
		System.out.println("Hello world");
	}*/

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
