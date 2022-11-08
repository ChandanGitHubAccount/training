package InsuranceDatabases.Controller;

import InsuranceDatabases.Model.Participated;
import InsuranceDatabases.Model.ParticipatedPk;
import InsuranceDatabases.Service.ParticipatedService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/participated/")
public class ParticipatedController {

    @Autowired
    private ParticipatedService participatedService;

    @PostMapping("addParticipated")
    public ResponseEntity<Participated> addParticipated(@RequestBody Participated participated){
        try {
            return ResponseEntity.of(Optional.of(participatedService.addParticipated(participated)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("getAllParticipatedDetails")
    public ResponseEntity<List<Participated>> getAllParticipatedDetails(){
        try {
            return ResponseEntity.of(Optional.of(participatedService.getAllParticipated()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

    @GetMapping("getParticularParticipatedDetails")
    public ResponseEntity<Optional<Participated>> getParticularParticipatedDetails(@RequestBody ParticipatedPk participatedPk){
        try {
            return ResponseEntity.of(Optional.of(participatedService.getParticularParticipatedDetails(participatedPk)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("getNumberOfPeopleMadeAccidentInParticularYear/{year}")
    public ResponseEntity<Long> getNumberOfPeopleMadeAccidentInParticularYear(@PathVariable int year){
        try {
            return ResponseEntity.of(Optional.of(participatedService.getNumberOfPeopleMadeAccidentInParticularYear(year)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("numberOfAccidentMadeByParticularPerson/{personName}")
    public ResponseEntity<Long> numberOfAccidentMadeByParticularPerson(@PathVariable String personName){
        try {
            return ResponseEntity.of(Optional.of(participatedService.numberOfAccidentMadeByParticularPerson(personName)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    @GetMapping("updateDamageAmount/{carRegNo}/{accidentReportNo}")
    public ResponseEntity<Integer> updateDamageAmount(@RequestBody int damageAmount, @PathVariable int carRegNo, @PathVariable int accidentReportNo){
        try {
            return ResponseEntity.of(Optional.of(participatedService.updateDamageAmounts(damageAmount, carRegNo, accidentReportNo)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
