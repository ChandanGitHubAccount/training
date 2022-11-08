package secondmajorevalustion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secondmajorevalustion.model.TrainRunningDates;

public interface TrainRunningDateRepository extends JpaRepository<TrainRunningDates, Integer> {
}
