package InsuranceDatabases.Controller;

import InsuranceDatabases.Model.Accident;
import InsuranceDatabases.Service.AccidentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/accident/")
public class AccidentController {

    @Autowired
    private AccidentService accidentService;

    @PostMapping("addAccident")
    public ResponseEntity<Accident> addAccident(@RequestBody Accident accident){
        try {
            return ResponseEntity.of(Optional.of(accidentService.addAccidents(accident)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("getAllAccidentDetails")
    public ResponseEntity<List<Accident>> getAllAccidentDetails(){
        try {
            return ResponseEntity.of(Optional.of(accidentService.getAllAccident()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

    @GetMapping("getParticularAccidentDetails/{accidentReportNo}")
    public ResponseEntity<Optional<Accident>> getParticularAccidentDetails(@PathVariable int accidentReportNo){
        try {
            return ResponseEntity.of(Optional.of(accidentService.getParticularAccidentDetails(accidentReportNo)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
