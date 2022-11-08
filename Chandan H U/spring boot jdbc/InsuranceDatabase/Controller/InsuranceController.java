package example.InsuranceDatabase.Controller;

import example.InsuranceDatabase.Model.*;
import example.InsuranceDatabase.Service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;

@RestController
public class InsuranceController {
    @Autowired
    CarOwnerServiceInterface carOwnerServiceInterface;
    @Autowired
    CarServiceInterface carServiceInterface;
    @Autowired
    PersonServiceInterface personServiceInterface;
    @Autowired
    ParticipatedServicesInterface participatedServicesInterface;
    @Autowired
    AccidentServiceInterface accidentServiceInterface;

    //person
    @PostMapping("addPerson/")
    Person addCarDetails(@RequestBody Person person) {
        return personServiceInterface.addPerson(person);
    }

    @DeleteMapping("removePerson/{personId}")
    Person removePersonByID(@PathVariable String personId) {return personServiceInterface.removePerson(personId).get(0);}

    @GetMapping("viewAllPersonDetails/")
    List<Person> viewAllPerson() {
        return personServiceInterface.viewAllPersonDetails();
    }

    //car
    @PostMapping("addCar/")
    Car addCarDetails(@RequestBody Car car) {
        return carServiceInterface.addCar(car);
    }

    @DeleteMapping("removeCar/{carRegNo}")
    Car removeCarByID(@PathVariable String carRegNo) {
        return carServiceInterface.remove(carRegNo).get(0);
    }

    @GetMapping("viewAllCarDetails/")
    List<Car> viewAllCar() {
        return carServiceInterface.viewAllCarDetails();
    }

    //Accident
    @PostMapping("addAccident/")
    Accident addAccidentDetails(@RequestBody Accident accident) {return accidentServiceInterface.addAccidents(accident);}

    @DeleteMapping("removeAccidents/{accidentReportNo}")
    Accident removeAccident(@PathVariable int accidentReportNo) {return accidentServiceInterface.removeAccidents(accidentReportNo).get(0);}

    @GetMapping("showAllAccidentDetails/")
    List<Accident> showAllAccident() {
        return accidentServiceInterface.showAllAccidentDetails();
    }

    //carOwners
    @GetMapping("viewCarOwnerDetails/")
    List<CarOwner> viewCarOwners() {
        return carOwnerServiceInterface.viewCarOwnerDetails();
    }

    //participated
    @GetMapping("totalNumberOfAccidentHappenInGivenYear/{year}")
    String totalNumberOfAccidentInGivenYear(@PathVariable int year) {return "Total number od accident in year " + year + " : " + participatedServicesInterface.totalNumberOfAccidentHappenInGivenYear(year);}

    @GetMapping("numberAccidentMadeByParticularPerson/{personName}")
    String numberAccidentByParticularPerson(@PathVariable String personName) {return "number_of_people_Made_Accident : " + participatedServicesInterface.numberAccidentMadeByParticularPerson(personName);}

    @GetMapping("viewAllParticipatedDetails/")
    List<Participated> viewAllParticipated() {
        return participatedServicesInterface.viewAllParticipatedDetails();
    }

    @PostMapping("updateParticipatedDamageAmount/{carRegNo}/{accidentReportNo}")
    Integer updateDamageAmount(@PathVariable String carRegNo, @PathVariable int accidentReportNo, @RequestBody Integer amount) {return participatedServicesInterface.updateParticipatedDamageAmount(carRegNo, accidentReportNo, amount);}
}
