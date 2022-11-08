package example.secondmajorevaluation.service;

import example.secondmajorevaluation.model.TrainDetails;
import example.secondmajorevaluation.model.TrainStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RailwayAdminService implements RailwayAdminInterface {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public TrainDetails addNewTrain(TrainDetails trainDetail) throws Exception {
        try {
            jdbcTemplate.update("Insert into trainDetails values(?,?,?,?)", trainDetail.getTrainNumber(),
                    trainDetail.getTrainDestination(), trainDetail.getTrainStartingPoint(), trainDetail.getTrainName());
            return jdbcTemplate.query("select * from trainDetails where trainNumber = ?",
                    new BeanPropertyRowMapper<>(TrainDetails.class), trainDetail.getTrainNumber()).get(0);
        } catch (Exception exception) {
            throw new Exception("Invalid Details");
        }
    }

    @Override
    public TrainDetails deleteTrain(int trainNumber) throws Exception {

        try {
            List<TrainDetails> trainDetail = jdbcTemplate.query("select * from trainDetails where trainNumber = ?",
                    new BeanPropertyRowMapper<>(TrainDetails.class), trainNumber);
            if (trainDetail.isEmpty())
                return null;
            else {
                jdbcTemplate.update("delete from trainDetails where trainNumber = ?", trainNumber);
                return trainDetail.get(0);
            }
        } catch (Exception exception) {
            throw new Exception("Invalid Details");
        }
    }

    @Override
    public List<TrainDetails> availableTrains() {
        try {
            return jdbcTemplate.query("select * from trainDetails",new BeanPropertyRowMapper<>(TrainDetails.class));
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public List<TrainStatus> showStatusOfAllTrains() {
       try {
           return jdbcTemplate.query("select * from trainStatus",new BeanPropertyRowMapper<>(TrainStatus.class));
       }catch (Exception exception){
           exception.printStackTrace();
           return null;
       }
    }

    @Override
    public TrainStatus addTrainStatus(TrainStatus trainStatus) {
        try {
            jdbcTemplate.update("Insert into trainStatus values (?,?,?,?,?)",trainStatus.getCoachType(),
                    trainStatus.getNumberOfSeats(),trainStatus.getTrainNumber(),trainStatus.getNumberOfSeatsBooked(),
                    trainStatus.getRunningDate());
            return jdbcTemplate.query("select * from trainStatus where trainNumber = ?",
                    new BeanPropertyRowMapper<>(TrainStatus.class),trainStatus.getTrainNumber()).get(0);
        }catch (DuplicateKeyException exception){
            System.out.println("Duplicate Primary Key Found.");
            return null;
        }catch (Exception exception){
            exception.printStackTrace();
            return null;
        }
    }

    @Override
    public TrainStatus deleteTrainStatus(int trainNumber) throws Exception {
        try {
            List<TrainStatus> trainStatus = jdbcTemplate.query("select * from trainStatus where trainNumber = ?",
                    new BeanPropertyRowMapper<>(TrainStatus.class), trainNumber);
            if (trainStatus.isEmpty())
                return null;
            else {
                jdbcTemplate.update("delete from trainStatus where trainNumber = ?", trainNumber);
                return trainStatus.get(0);
            }
        } catch (Exception exception) {
            exception.printStackTrace();
            return null;
        }
    }

}
