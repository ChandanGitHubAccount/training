package InsuranceDatabases.Service;

import InsuranceDatabases.Model.Person;

import java.util.List;
import java.util.Optional;

public interface PersonServiceInterface {
    Person addPerson(Person person);

    List<Person> getAllPerson();

    Optional<Person> getParticularPersonDetails(int driverId);
}
