package secondmajorevalustion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secondmajorevalustion.model.PassengerDetails;

public interface PassengerRepository extends JpaRepository<PassengerDetails,Integer> {
}
