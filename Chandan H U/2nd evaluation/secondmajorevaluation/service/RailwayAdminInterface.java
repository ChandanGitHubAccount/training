package example.secondmajorevaluation.service;

import example.secondmajorevaluation.model.TrainDetails;
import example.secondmajorevaluation.model.TrainStatus;

import java.util.List;

public interface RailwayAdminInterface {
    TrainDetails addNewTrain(TrainDetails trainDetail) throws Exception;

    TrainDetails deleteTrain(int trainNumber) throws Exception;

    List<TrainDetails> availableTrains();

    TrainStatus addTrainStatus(TrainStatus trainStatus);

    TrainStatus deleteTrainStatus(int trainNumber) throws Exception;

    List<TrainStatus> showStatusOfAllTrains();
}
