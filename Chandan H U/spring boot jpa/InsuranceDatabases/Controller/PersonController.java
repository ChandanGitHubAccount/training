package InsuranceDatabases.Controller;

import InsuranceDatabases.Model.Person;
import InsuranceDatabases.Service.PersonService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/person/")
public class PersonController {

    @Autowired
    private PersonService personService;

    @PostMapping("addPerson")
    public ResponseEntity<Person> addPerson(@RequestBody Person person){
        try {
            return ResponseEntity.of(Optional.of(personService.addPerson(person)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @GetMapping("getAllPersonDetails")
    public ResponseEntity<List<Person>> getAllPersonDetails(){
        try {
            return ResponseEntity.of(Optional.of(personService.getAllPerson()));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }
    }

    @GetMapping("getParticularCarDetails/{carRegNo}")
    public ResponseEntity<Optional<Person>> getParticularPersonDetails(@PathVariable int driverId){
        try {
            return ResponseEntity.of(Optional.of(personService.getParticularPersonDetails(driverId)));
        }catch (Exception exception){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
