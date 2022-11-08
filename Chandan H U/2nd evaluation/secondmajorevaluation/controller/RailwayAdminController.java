package example.secondmajorevaluation.controller;

import example.secondmajorevaluation.model.TrainDetails;
import example.secondmajorevaluation.model.TrainStatus;
import example.secondmajorevaluation.service.RailwayAdminInterface;
import example.secondmajorevaluation.service.TicketStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/railway-admin")
public class RailwayAdminController {

    @Autowired
    private RailwayAdminInterface railwayAdminInterface;

    @PostMapping("/add-new-train")
    ResponseEntity<TrainDetails> addNewTrain(@ModelAttribute TrainDetails trainDetail) {
        try {
            return ResponseEntity.of(Optional.of(railwayAdminInterface.addNewTrain(trainDetail)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @DeleteMapping("/delete-train")
    ResponseEntity<TrainDetails> deleteTrainDetails(@RequestParam int trainNumber) {
        try {
            return ResponseEntity.of(Optional.of(railwayAdminInterface.deleteTrain(trainNumber)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/view-train-details")
    ResponseEntity<List<TrainDetails>> viewAllTrainDetails() {
        try {
            return ResponseEntity.of(Optional.of(railwayAdminInterface.availableTrains()));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

    @PostMapping("/add-train-status")
    ResponseEntity<TrainStatus> addNewTrainStatus(@RequestBody TrainStatus TrainStatus) {
        try {
            return ResponseEntity.of(Optional.of(railwayAdminInterface.addTrainStatus(TrainStatus)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @DeleteMapping("/delete-train-status")
    ResponseEntity<TrainStatus> deleteTrainStatus(int trainNumber) {
        try {
            return ResponseEntity.of(Optional.of(railwayAdminInterface.deleteTrainStatus(trainNumber)));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("/view-train-status")
    ResponseEntity<List<TrainStatus>> viewAllTrainStatus() {
        try {
            return ResponseEntity.of(Optional.of(railwayAdminInterface.showStatusOfAllTrains()));
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

}
