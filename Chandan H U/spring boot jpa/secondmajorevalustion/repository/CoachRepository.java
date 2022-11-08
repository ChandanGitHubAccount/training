package secondmajorevalustion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secondmajorevalustion.model.TrainCoaches;

public interface CoachRepository extends JpaRepository<TrainCoaches,Integer> {
}
