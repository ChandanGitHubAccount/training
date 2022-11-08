package secondmajorevalustion.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import secondmajorevalustion.model.TrainDetails;
import secondmajorevalustion.model.TrainRunningDates;

import java.util.List;

public interface TrainRepository extends JpaRepository<TrainDetails,Integer> {
    List<TrainDetails> findByTrainNumberAndTrainRunningDates(int trainNumber , TrainRunningDates Date);
}
